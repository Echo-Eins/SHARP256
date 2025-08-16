// src/connectivity/ice/mod.rs
//! ICE (Interactive Connectivity Establishment) реализация на основе webrtc-rs
//!
//! Полная RFC 8445 совместимая реализация с интеграцией webrtc-rs библиотеки.
//! Включает в себя:
//! - Candidate gathering (сбор кандидатов)
//! - Connectivity checks (проверки соединений)
//! - Nomination process (процесс номинации)
//! - Полная интеграция с webrtc-rs
//! - Отказоустойчивость и мониторинг

#[cfg(feature = "webrtc-ice-stack")]
use anyhow::Result;
#[cfg(feature = "webrtc-ice-stack")]
use std::sync::Arc;
#[cfg(feature = "webrtc-ice-stack")]
use std::time::Duration;
#[cfg(feature = "webrtc-ice-stack")]
use tokio::sync::mpsc;

// === ОСНОВНЫЕ МОДУЛИ ===

// Основной ICE Agent - координирует все процессы
#[cfg(feature = "webrtc-ice-stack")]
pub mod agent;

// Сбор кандидатов
#[cfg(feature = "webrtc-ice-stack")]
pub mod gathering;

// Connectivity checks
#[cfg(feature = "webrtc-ice-stack")]
pub mod connectivity;

// Nomination процесс
#[cfg(feature = "webrtc-ice-stack")]
pub mod nomination;

// Utility функции и конвертация типов
#[cfg(feature = "webrtc-ice-stack")]
pub mod utils;

// === RE-EXPORTS ===

// Основные типы
#[cfg(feature = "webrtc-ice-stack")]
pub use agent::{
    IceAgent, IceAgentConfig, IceAgentState, IceProcessState, IceAgentStats
};

// Gathering
#[cfg(feature = "webrtc-ice-stack")]
pub use gathering::{
    CandidateGatherer, GatheringState, GatheringProgress, GatheringConfig,
    GatheringStats, GathererFactory
};

// Connectivity
#[cfg(feature = "webrtc-ice-stack")]
pub use connectivity::{
    ConnectivityChecker, ConnectivityState, ConnectivityConfig, ConnectivityStats,
    CheckResult, CheckType, ConnectivityCheckerFactory
};

// Nomination
#[cfg(feature = "webrtc-ice-stack")]
pub use nomination::{
    CandidateNominator, NominationState, NominationMethod, NominationConfig,
    NominationStats, NominationResult, NominatorFactory
};

// Utils
#[cfg(feature = "webrtc-ice-stack")]
pub use utils::{
    webrtc_candidate_to_candidate, candidate_type_to_webrtc_candidate_type,
    webrtc_candidate_type_to_candidate_type, webrtc_pair_to_candidate_pair,
    calculate_candidate_priority, calculate_pair_priority, generate_foundation,
    determine_nat_type, NatType, filter_candidates, CandidateFilter, IpVersion,
    is_valid_candidate_address, is_public_address,
    sort_candidates_by_priority, sort_pairs_by_priority, get_default_local_address
};

// Importing common types
#[cfg(feature = "webrtc-ice-stack")]
use crate::connectivity::{Candidate, CandidatePair, ConnectivityCheckResult};
#[cfg(feature = "webrtc-ice-stack")]
use crate::connectivity::config::IceConfig;

/// ICE Connection wrapper для Transport trait
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone)]
pub struct IceConnection {
    conn: Arc<dyn webrtc::ice::conn::Conn + Send + Sync>,
    selected_pair: CandidatePair,
}

#[cfg(feature = "webrtc-ice-stack")]
impl IceConnection {
    pub fn new(
        conn: Arc<dyn webrtc::ice::conn::Conn + Send + Sync>,
        selected_pair: CandidatePair,
    ) -> Self {
        Self { conn, selected_pair }
    }

    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        self.conn.send(data).await.map_err(Into::into)
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.conn.recv(buf).await.map_err(Into::into)
    }

    pub fn selected_pair(&self) -> &CandidatePair {
        &self.selected_pair
    }

    pub async fn close(&self) -> Result<()> {
        self.conn.close().await.map_err(Into::into)
    }

    /// Получение статистики соединения
    pub fn get_stats(&self) -> IceConnectionStats {
        IceConnectionStats {
            selected_pair: self.selected_pair.clone(),
            bytes_sent: 0, // TODO: Получать из webrtc::ice::conn::Conn если доступно
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            connection_state: IceConnectionState::Connected,
        }
    }
}

/// Статистика ICE соединения
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone)]
pub struct IceConnectionStats {
    pub selected_pair: CandidatePair,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_state: IceConnectionState,
}

/// Состояние ICE соединения
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceConnectionState {
    New,
    Checking,
    Connected,
    Completed,
    Failed,
    Disconnected,
    Closed,
}

/// События ICE процесса
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone)]
pub enum IceEvent {
    /// ICE процесс начался
    IceProcessStarted,
    /// Новый кандидат собран
    CandidateGathered(Candidate),
    /// Сбор кандидатов завершен
    GatheringComplete,
    /// Начались connectivity checks
    ConnectivityChecksStarted,
    /// Результат connectivity check
    ConnectivityCheckCompleted(ConnectivityCheckResult),
    /// Пара кандидатов номинирована
    CandidatePairNominated(CandidatePair),
    /// ICE соединение установлено
    ConnectionEstablished(IceConnection),
    /// ICE ошибка
    Error(String),
}

/// Состояние ICE агента
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceAgentState {
    /// Начальное состояние
    New,
    /// Сбор кандидатов
    Gathering,
    /// Connectivity checks
    Connecting,
    /// Соединение установлено
    Connected,
    /// Соединение отключено
    Disconnected,
    /// Ошибка
    Failed,
    /// Закрыто
    Closed,
}

/// === ФАБРИКИ И УТИЛИТЫ ===

/// Фабрика для создания ICE компонентов
#[cfg(feature = "webrtc-ice-stack")]
pub struct IceComponentFactory;

#[cfg(feature = "webrtc-ice-stack")]
impl IceComponentFactory {
    /// Создание полного ICE стека
    pub async fn create_ice_stack(
        ice_config: IceConfig,
        controlling: bool,
    ) -> Result<IceStack> {
        let agent = agent::IceAgent::new(ice_config, controlling).await?;

        Ok(IceStack {
            agent: Arc::new(agent),
        })
    }

    /// Создание ICE стека для тестирования
    pub async fn create_test_stack() -> Result<IceStack> {
        let ice_config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            connectivity_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        Self::create_ice_stack(ice_config, true).await
    }

    /// Создание пары связанных ICE стеков
    pub async fn create_ice_pair(ice_config: IceConfig) -> Result<(IceStack, IceStack)> {
        let controlling_stack = Self::create_ice_stack(ice_config.clone(), true).await?;
        let controlled_stack = Self::create_ice_stack(ice_config, false).await?;

        Ok((controlling_stack, controlled_stack))
    }
}

/// Полный ICE стек
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug)]
pub struct IceStack {
    agent: Arc<IceAgent>,
}

#[cfg(feature = "webrtc-ice-stack")]
impl IceStack {
    /// Полный ICE процесс
    pub async fn perform_ice(&self) -> Result<IceConnection> {
        self.agent.perform_ice_process().await
    }

    /// Сбор кандидатов
    pub async fn gather_candidates(&self) -> Result<Vec<Candidate>> {
        self.agent.gather_candidates_with_progress().await
    }

    /// Добавление удаленного кандидата
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> Result<()> {
        self.agent.add_remote_candidate(candidate).await
    }

    /// Получение локальных кандидатов
    pub async fn get_local_candidates(&self) -> Vec<Candidate> {
        self.agent.get_local_candidates().await
    }

    /// Получение состояния процесса
    pub async fn get_process_state(&self) -> IceProcessState {
        self.agent.get_process_state().await
    }

    /// Получение статистики
    pub async fn get_stats(&self) -> IceAgentStats {
        self.agent.get_stats().await
    }

    /// Получение receiver для событий
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<IceEvent>> {
        self.agent.take_event_receiver().await
    }

    /// Проверка соединения
    pub async fn is_connected(&self) -> bool {
        self.agent.is_connected().await
    }

    /// Restart ICE
    pub async fn restart(&self) -> Result<()> {
        self.agent.restart_ice().await
    }

    /// Остановка ICE стека
    pub async fn shutdown(&self) -> Result<()> {
        self.agent.shutdown().await
    }
}

/// === КОНСТАНТЫ И ВЕРСИИ ===

/// Версия ICE реализации
#[cfg(feature = "webrtc-ice-stack")]
pub const ICE_VERSION: &str = "1.0.0";

/// Поддерживаемые RFC спецификации
#[cfg(feature = "webrtc-ice-stack")]
pub const SUPPORTED_SPECS: &[&str] = &[
    "RFC 8445 - Interactive Connectivity Establishment (ICE)",
    "RFC 8838 - Trickle ICE",
    "RFC 7675 - STUN Usage for Consent Freshness",
    "RFC 8421 - Guidelines for Multihomed and IPv4/IPv6 Dual-Stack ICE",
];

/// Возможности ICE реализации
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone)]
pub struct IceCapabilities {
    /// Полная поддержка ICE (RFC 8445)
    pub full_ice: bool,
    /// Trickle ICE поддержка (RFC 8838)
    pub trickle_ice: bool,
    /// Consent freshness (RFC 7675)
    pub consent_freshness: bool,
    /// IPv4/IPv6 dual stack
    pub dual_stack: bool,
    /// TCP кандидаты
    pub tcp_candidates: bool,
    /// mDNS кандидаты
    pub mdns_candidates: bool,
    /// Aggressive nomination
    pub aggressive_nomination: bool,
    /// Bundle поддержка
    pub bundle_support: bool,
    /// WebRTC integration
    pub webrtc_integration: bool,
}

#[cfg(feature = "webrtc-ice-stack")]
impl Default for IceCapabilities {
    fn default() -> Self {
        Self {
            full_ice: true,
            trickle_ice: true,
            consent_freshness: true,
            dual_stack: true,
            tcp_candidates: false,  // Пока не реализовано
            mdns_candidates: false, // Пока не реализовано
            aggressive_nomination: true,
            bundle_support: true,
            webrtc_integration: true,
        }
    }
}

/// Получение возможностей ICE реализации
#[cfg(feature = "webrtc-ice-stack")]
pub fn get_ice_capabilities() -> IceCapabilities {
    IceCapabilities::default()
}

/// Валидация ICE конфигурации
#[cfg(feature = "webrtc-ice-stack")]
pub fn validate_ice_config(config: &IceConfig) -> Result<()> {
    // Проверка STUN серверов
    if config.stun_servers.is_empty() && config.turn_servers.is_empty() {
        return Err(anyhow::anyhow!("At least one STUN or TURN server must be configured"));
    }

    // Проверка таймаутов
    if config.gathering_timeout < Duration::from_secs(1) {
        return Err(anyhow::anyhow!("Gathering timeout too short"));
    }

    if config.connectivity_timeout < Duration::from_secs(1) {
        return Err(anyhow::anyhow!("Connectivity timeout too short"));
    }

    // Проверка лимитов
    if config.max_candidate_pairs == 0 {
        return Err(anyhow::anyhow!("Max candidate pairs must be greater than 0"));
    }

    if config.max_candidate_pairs > 1000 {
        return Err(anyhow::anyhow!("Max candidate pairs too large (>1000)"));
    }

    Ok(())
}

/// Создание оптимизированной ICE конфигурации для P2P
#[cfg(feature = "webrtc-ice-stack")]
pub fn create_p2p_ice_config() -> IceConfig {
    IceConfig {
        stun_servers: vec![
            "stun:stun.l.google.com:19302".to_string(),
            "stun:stun1.l.google.com:19302".to_string(),
        ],
        turn_servers: vec![], // Добавить TURN серверы при необходимости
        controlling_role: Some(true),
        trickle_ice: true,
        gathering_timeout: Duration::from_secs(10),
        connectivity_timeout: Duration::from_secs(30),
        check_interval: Duration::from_millis(50),
        max_candidate_pairs: 50,
        enable_ipv6: true,
        enable_host_candidates: true,
        enable_srflx_candidates: true,
        enable_relay_candidates: true,
        candidate_priorities: Default::default(),
    }
}

/// Создание ICE конфигурации для тестирования
#[cfg(feature = "webrtc-ice-stack")]
pub fn create_test_ice_config() -> IceConfig {
    IceConfig {
        stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
        turn_servers: vec![],
        controlling_role: Some(true),
        trickle_ice: true,
        gathering_timeout: Duration::from_secs(5),
        connectivity_timeout: Duration::from_secs(10),
        check_interval: Duration::from_millis(25),
        max_candidate_pairs: 20,
        enable_ipv6: false, // Упрощаем для тестов
        enable_host_candidates: true,
        enable_srflx_candidates: true,
        enable_relay_candidates: false,
        candidate_priorities: Default::default(),
    }
}

/// === MOCK РЕАЛИЗАЦИЯ ===

/// Mock реализация для тестирования без webrtc-ice-stack
#[cfg(not(feature = "webrtc-ice-stack"))]
pub mod mock {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Mock ICE Agent для сборки без webrtc-ice-stack
    #[derive(Debug)]
    pub struct MockIceAgent;

    impl MockIceAgent {
        pub async fn new(_config: crate::connectivity::config::IceConfig, _controlling: bool) -> Result<Self> {
            Ok(Self)
        }

        pub async fn gather_candidates_with_progress(
            &self,
            _progress_tx: mpsc::UnboundedSender<crate::connectivity::ConnectivityEvent>,
        ) -> Result<Vec<crate::connectivity::Candidate>> {
            Ok(vec![])
        }

        pub async fn add_remote_candidate(&self, _candidate: crate::connectivity::Candidate) -> Result<()> {
            Ok(())
        }

        pub async fn perform_connectivity_checks(&self) -> Result<Vec<crate::connectivity::ConnectivityCheckResult>> {
            Ok(vec![])
        }

        pub async fn nominate_pair(&self, _pair: crate::connectivity::CandidatePair) -> Result<Option<crate::connectivity::CandidatePair>> {
            Ok(None)
        }

        pub async fn get_connection(&self) -> Result<Arc<dyn std::fmt::Debug + Send + Sync>> {
            Err(anyhow::anyhow!("WebRTC ICE not available"))
        }
    }

    /// Mock IceStack
    #[derive(Debug)]
    pub struct MockIceStack;

    impl MockIceStack {
        pub async fn perform_ice(&self) -> Result<()> {
            Err(anyhow::anyhow!("WebRTC ICE not available"))
        }
    }

    pub type IceAgent = MockIceAgent;
    pub type IceStack = MockIceStack;
}

/// Условные re-exports в зависимости от feature
#[cfg(feature = "webrtc-ice-stack")]
pub use agent::IceAgent as PublicIceAgent;
#[cfg(feature = "webrtc-ice-stack")]
pub use IceStack as PublicIceStack;

#[cfg(not(feature = "webrtc-ice-stack"))]
pub use mock::{IceAgent as PublicIceAgent, IceStack as PublicIceStack};

/// === INTEGRATION TESTS ===

#[cfg(all(test, feature = "webrtc-ice-stack"))]
mod integration_tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_ice_stack_creation() {
        let stack = IceComponentFactory::create_test_stack().await;
        assert!(stack.is_ok());
    }

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = create_test_ice_config();
        let agent = agent::IceAgent::new(config, true).await;
        assert!(agent.is_ok());
    }

    #[tokio::test]
    async fn test_candidate_gathering() {
        let stack = IceComponentFactory::create_test_stack().await.unwrap();

        // В реальности это должно собрать кандидаты
        // Для теста проверяем, что метод не паникует
        let result = timeout(Duration::from_secs(5), stack.gather_candidates()).await;
        // Может быть ошибка из-за отсутствия сети, но не должно паниковать
        println!("Gathering result: {:?}", result);
    }

    #[tokio::test]
    async fn test_ice_capabilities() {
        let capabilities = get_ice_capabilities();
        assert!(capabilities.full_ice);
        assert!(capabilities.webrtc_integration);
    }

    #[tokio::test]
    async fn test_config_validation() {
        let valid_config = create_test_ice_config();
        assert!(validate_ice_config(&valid_config).is_ok());

        let invalid_config = IceConfig {
            stun_servers: vec![],
            turn_servers: vec![],
            gathering_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        assert!(validate_ice_config(&invalid_config).is_err());
    }
}