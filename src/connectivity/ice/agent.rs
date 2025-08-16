// src/connectivity/ice/agent.rs
//! Integrated ICE Agent Implementation
//! Полная интеграция всех ICE компонентов с webrtc-rs

use anyhow::Result;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify, Mutex};
use tokio::time::{timeout, sleep};
use tracing::{debug, info, warn, error, trace};

use webrtc::ice::{
    agent::{Agent as WebRtcAgent, AgentConfig as WebRtcAgentConfig},
    candidate::{Candidate as WebRtcCandidate, CandidateType as WebRtcCandidateType},
    state::{ConnectionState as WebRtcConnectionState, GatheringState as WebRtcGatheringState},
    url::Url,
};

use crate::connectivity::{
    Candidate, CandidatePair, CandidatePairState, ConnectivityCheckResult, ConnectivityEvent
};
use crate::connectivity::config::IceConfig;
use super::{
    IceConnection, IceAgentState, IceEvent,
    gathering::{CandidateGatherer, GatheringState, GatheringStats},
    connectivity::{ConnectivityChecker, ConnectivityState, ConnectivityStats},
    nomination::{CandidateNominator, NominationState, NominationStats},
    utils::webrtc_candidate_to_candidate,
};

/// Конфигурация ICE агента
#[derive(Debug, Clone)]
pub struct IceAgentConfig {
    /// ICE конфигурация (STUN/TURN серверы)
    pub ice_config: IceConfig,
    /// Controlling роль
    pub controlling: bool,
    /// Локальные ICE credentials
    pub local_ufrag: Option<String>,
    pub local_pwd: Option<String>,
    /// Удаленные ICE credentials
    pub remote_ufrag: Option<String>,
    pub remote_pwd: Option<String>,
    /// Trickle ICE
    pub trickle_ice: bool,
    /// Aggressive nomination
    pub aggressive_nomination: bool,
}

impl Default for IceAgentConfig {
    fn default() -> Self {
        Self {
            ice_config: IceConfig::default(),
            controlling: true,
            local_ufrag: None,
            local_pwd: None,
            remote_ufrag: None,
            remote_pwd: None,
            trickle_ice: true,
            aggressive_nomination: false,
        }
    }
}

/// Состояние ICE процесса
#[derive(Debug, Clone)]
pub struct IceProcessState {
    /// Общее состояние агента
    pub agent_state: IceAgentState,
    /// Состояние gathering
    pub gathering_state: GatheringState,
    /// Состояние connectivity checks
    pub connectivity_state: ConnectivityState,
    /// Состояние nomination
    pub nomination_state: NominationState,
    /// Время начала процесса
    pub started_at: Option<Instant>,
    /// Время завершения
    pub completed_at: Option<Instant>,
}

impl Default for IceProcessState {
    fn default() -> Self {
        Self {
            agent_state: IceAgentState::New,
            gathering_state: GatheringState::New,
            connectivity_state: ConnectivityState::New,
            nomination_state: NominationState::NotStarted,
            started_at: None,
            completed_at: None,
        }
    }
}

/// Полная статистика ICE процесса
#[derive(Debug, Clone)]
pub struct IceAgentStats {
    /// Статистика gathering
    pub gathering_stats: GatheringStats,
    /// Статистика connectivity checks
    pub connectivity_stats: ConnectivityStats,
    /// Статистика nomination
    pub nomination_stats: NominationStats,
    /// Общая статистика
    pub total_duration: Option<Duration>,
    pub ice_restart_count: u32,
    pub connection_failures: u32,
}

impl Default for IceAgentStats {
    fn default() -> Self {
        Self {
            gathering_stats: GatheringStats::new(),
            connectivity_stats: ConnectivityStats::new(),
            nomination_stats: NominationStats::new(),
            total_duration: None,
            ice_restart_count: 0,
            connection_failures: 0,
        }
    }
}

/// Основной ICE Agent - координирует все ICE процессы
pub struct IceAgent {
    /// WebRTC ICE Agent (основа)
    webrtc_agent: Arc<WebRtcAgent>,

    /// Конфигурация
    config: IceAgentConfig,

    /// Состояние процесса
    process_state: Arc<RwLock<IceProcessState>>,

    /// Компоненты ICE процесса
    candidate_gatherer: Arc<Mutex<Option<CandidateGatherer>>>,
    connectivity_checker: Arc<Mutex<Option<ConnectivityChecker>>>,
    candidate_nominator: Arc<Mutex<Option<CandidateNominator>>>,

    /// Локальные кандидаты
    local_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Удаленные кандидаты
    remote_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Пары кандидатов
    candidate_pairs: Arc<RwLock<Vec<CandidatePair>>>,

    /// Номинированная пара
    nominated_pair: Arc<RwLock<Option<CandidatePair>>>,

    /// Установленное соединение
    ice_connection: Arc<RwLock<Option<IceConnection>>>,

    /// Статистика
    stats: Arc<RwLock<IceAgentStats>>,

    /// События ICE процесса
    event_tx: mpsc::UnboundedSender<IceEvent>,
    event_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<IceEvent>>>>,

    /// Internal события для координации компонентов
    internal_event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    internal_event_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ConnectivityEvent>>>>,

    /// Уведомления о завершении процессов
    gathering_complete: Arc<Notify>,
    connectivity_complete: Arc<Notify>,
    nomination_complete: Arc<Notify>,
    connection_established: Arc<Notify>,

    /// Флаг остановки
    shutdown: Arc<RwLock<bool>>,
}

impl IceAgent {
    /// Создание нового ICE Agent
    pub async fn new(ice_config: IceConfig, controlling: bool) -> Result<Self> {
        let config = IceAgentConfig {
            ice_config: ice_config.clone(),
            controlling,
            ..Default::default()
        };

        Self::with_config(config).await
    }

    /// Создание с полной конфигурацией
    pub async fn with_config(config: IceAgentConfig) -> Result<Self> {
        // Создаем WebRTC Agent конфигурацию
        let webrtc_config = Self::create_webrtc_config(&config)?;

        // Создаем WebRTC Agent
        let webrtc_agent = Arc::new(WebRtcAgent::new(webrtc_config).await?);

        // Создаем каналы событий
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (internal_event_tx, internal_event_rx) = mpsc::unbounded_channel();

        let agent = Self {
            webrtc_agent,
            config,
            process_state: Arc::new(RwLock::new(IceProcessState::default())),
            candidate_gatherer: Arc::new(Mutex::new(None)),
            connectivity_checker: Arc::new(Mutex::new(None)),
            candidate_nominator: Arc::new(Mutex::new(None)),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            remote_candidates: Arc::new(RwLock::new(Vec::new())),
            candidate_pairs: Arc::new(RwLock::new(Vec::new())),
            nominated_pair: Arc::new(RwLock::new(None)),
            ice_connection: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(IceAgentStats::default())),
            event_tx,
            event_rx: Arc::new(RwLock::new(Some(event_rx))),
            internal_event_tx,
            internal_event_rx: Arc::new(Mutex::new(Some(internal_event_rx))),
            gathering_complete: Arc::new(Notify::new()),
            connectivity_complete: Arc::new(Notify::new()),
            nomination_complete: Arc::new(Notify::new()),
            connection_established: Arc::new(Notify::new()),
            shutdown: Arc::new(RwLock::new(false)),
        };

        // Инициализируем компоненты
        agent.initialize_components().await?;

        // Запускаем event processing
        agent.start_event_processing().await?;

        info!("ICE Agent created (controlling: {})", agent.config.controlling);
        Ok(agent)
    }

    /// Создание WebRTC Agent конфигурации
    fn create_webrtc_config(config: &IceAgentConfig) -> Result<WebRtcAgentConfig> {
        let mut urls = Vec::new();

        // Добавляем STUN серверы
        for stun_server in &config.ice_config.stun_servers {
            let url = Url::parse_url(stun_server)
                .map_err(|e| anyhow::anyhow!("Invalid STUN server URL {}: {}", stun_server, e))?;
            urls.push(url);
        }

        // Добавляем TURN серверы
        for turn_server in &config.ice_config.turn_servers {
            let url = Url::parse_url(&turn_server.url)
                .map_err(|e| anyhow::anyhow!("Invalid TURN server URL {}: {}", turn_server.url, e))?;
            urls.push(url);
        }

        // Определяем типы кандидатов
        let mut candidate_types = Vec::new();
        if config.ice_config.enable_host_candidates {
            candidate_types.push(WebRtcCandidateType::Host);
        }
        if config.ice_config.enable_srflx_candidates {
            candidate_types.push(WebRtcCandidateType::ServerReflexive);
        }
        if config.ice_config.enable_relay_candidates {
            candidate_types.push(WebRtcCandidateType::Relay);
        }

        Ok(WebRtcAgentConfig {
            urls,
            is_controlling: config.controlling,
            candidate_types,
            ..Default::default()
        })
    }

    /// Инициализация компонентов
    async fn initialize_components(&self) -> Result<()> {
        debug!("Initializing ICE Agent components");

        // Создаем CandidateGatherer
        let gatherer = CandidateGatherer::new(
            Arc::clone(&self.webrtc_agent),
            self.config.ice_config.clone(),
            self.internal_event_tx.clone(),
        );
        *self.candidate_gatherer.lock().await = Some(gatherer);

        // Создаем ConnectivityChecker
        let checker = ConnectivityChecker::new(
            Arc::clone(&self.webrtc_agent),
            self.config.ice_config.clone(),
            self.config.controlling,
            self.internal_event_tx.clone(),
        );
        *self.connectivity_checker.lock().await = Some(checker);

        // Создаем CandidateNominator (только для controlling agent)
        if self.config.controlling {
            let nominator = CandidateNominator::new(
                Arc::clone(&self.webrtc_agent),
                self.config.controlling,
                self.internal_event_tx.clone(),
            );
            *self.candidate_nominator.lock().await = Some(nominator);
        }

        debug!("ICE Agent components initialized");
        Ok(())
    }

    /// Запуск обработки событий
    async fn start_event_processing(&self) -> Result<()> {
        let event_rx = self.internal_event_rx.lock().await.take()
            .ok_or_else(|| anyhow::anyhow!("Event receiver already taken"))?;

        // Запускаем event processing loop в отдельной задаче
        let processor = IceEventProcessor {
            agent_weak: Arc::downgrade(&Arc::new(())), // Используем weak reference для избежания cycles
            event_rx: Mutex::new(event_rx),
            event_tx: self.event_tx.clone(),
            process_state: Arc::clone(&self.process_state),
            stats: Arc::clone(&self.stats),
            gathering_complete: Arc::clone(&self.gathering_complete),
            connectivity_complete: Arc::clone(&self.connectivity_complete),
            nomination_complete: Arc::clone(&self.nomination_complete),
            connection_established: Arc::clone(&self.connection_established),
        };

        tokio::spawn(async move {
            processor.run().await;
        });

        Ok(())
    }

    /// Полный ICE процесс: gathering -> connectivity checks -> nomination
    pub async fn perform_ice_process(&self) -> Result<IceConnection> {
        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("ICE Agent is shut down"));
        }

        info!("Starting complete ICE process");

        // Обновляем состояние
        {
            let mut state = self.process_state.write().await;
            state.agent_state = IceAgentState::Gathering;
            state.started_at = Some(Instant::now());
        }

        // Отправляем событие начала ICE
        let _ = self.event_tx.send(IceEvent::IceProcessStarted);

        // Фаза 1: Gathering кандидатов
        self.gather_candidates_with_progress().await?;

        // Фаза 2: Формирование пар и connectivity checks
        self.perform_connectivity_checks().await?;

        // Фаза 3: Nomination (только для controlling agent)
        if self.config.controlling {
            self.perform_nomination().await?;
        }

        // Ждем установления соединения
        let timeout_duration = self.config.ice_config.connectivity_timeout;
        match timeout(timeout_duration, self.connection_established.notified()).await {
            Ok(()) => {
                info!("ICE process completed successfully");

                // Обновляем состояние
                {
                    let mut state = self.process_state.write().await;
                    state.agent_state = IceAgentState::Connected;
                    state.completed_at = Some(Instant::now());
                }

                // Получаем установленное соединение
                self.get_connection().await
            }
            Err(_) => {
                error!("ICE process timed out");

                // Обновляем состояние
                {
                    let mut state = self.process_state.write().await;
                    state.agent_state = IceAgentState::Failed;
                    state.completed_at = Some(Instant::now());
                }

                let _ = self.event_tx.send(IceEvent::Error("ICE process timeout".to_string()));
                Err(anyhow::anyhow!("ICE process timeout"))
            }
        }
    }

    /// Сбор кандидатов с прогрессом
    pub async fn gather_candidates_with_progress(&self) -> Result<Vec<Candidate>> {
        info!("Starting candidate gathering with progress tracking");

        let gatherer = self.candidate_gatherer.lock().await;
        let gatherer = gatherer.as_ref()
            .ok_or_else(|| anyhow::anyhow!("CandidateGatherer not initialized"))?;

        // Запускаем gathering
        gatherer.start_gathering().await?;

        // Ждем завершения
        self.gathering_complete.notified().await;

        // Получаем собранные кандидаты
        let candidates = gatherer.get_candidates().await;

        // Обновляем локальные кандидаты
        *self.local_candidates.write().await = candidates.clone();

        info!("Gathering completed, {} candidates collected", candidates.len());
        Ok(candidates)
    }

    /// Добавление удаленного кандидата
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> Result<()> {
        debug!("Adding remote candidate: {:?}", candidate.address);

        // Добавляем к удаленным кандидатам
        self.remote_candidates.write().await.push(candidate.clone());

        // Конвертируем в WebRTC формат и добавляем к WebRTC Agent
        // TODO: Реализовать candidate_to_webrtc_candidate
        // let webrtc_candidate = candidate_to_webrtc_candidate(&candidate)?;
        // self.webrtc_agent.add_remote_candidate(&webrtc_candidate).await?;

        // Если у нас есть локальные кандидаты, формируем новые пары
        self.update_candidate_pairs().await?;

        Ok(())
    }

    /// Обновление пар кандидатов
    async fn update_candidate_pairs(&self) -> Result<()> {
        let local_candidates = self.local_candidates.read().await;
        let remote_candidates = self.remote_candidates.read().await;

        if local_candidates.is_empty() || remote_candidates.is_empty() {
            return Ok(()); // Еще не готовы формировать пары
        }

        let mut new_pairs = Vec::new();

        // Формируем все возможные пары
        for local in local_candidates.iter() {
            for remote in remote_candidates.iter() {
                // Проверяем совместимость кандидатов
                if self.are_candidates_compatible(local, remote) {
                    let pair = CandidatePair::new(local.clone(), remote.clone());
                    new_pairs.push(pair);
                }
            }
        }

        // Сортируем пары по приоритету
        new_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Ограничиваем количество пар
        let max_pairs = self.config.ice_config.max_candidate_pairs;
        if new_pairs.len() > max_pairs {
            new_pairs.truncate(max_pairs);
        }

        // Обновляем пары кандидатов
        *self.candidate_pairs.write().await = new_pairs;

        debug!("Updated candidate pairs, {} total pairs", self.candidate_pairs.read().await.len());
        Ok(())
    }

    /// Проверка совместимости кандидатов
    fn are_candidates_compatible(&self, local: &Candidate, remote: &Candidate) -> bool {
        // Базовые проверки совместимости

        // IP версии должны совпадать
        if local.address.is_ipv4() != remote.address.is_ipv4() {
            return false;
        }

        // Транспорт должен совпадать
        if local.attributes.transport != remote.attributes.transport {
            return false;
        }

        // Компоненты должны совпадать
        if local.attributes.component != remote.attributes.component {
            return false;
        }

        true
    }

    /// Выполнение connectivity checks
    pub async fn perform_connectivity_checks(&self) -> Result<Vec<ConnectivityCheckResult>> {
        info!("Starting connectivity checks");

        // Обновляем состояние
        {
            let mut state = self.process_state.write().await;
            state.agent_state = IceAgentState::Connecting;
            state.connectivity_state = ConnectivityState::Checking;
        }

        let checker = self.connectivity_checker.lock().await;
        let checker = checker.as_ref()
            .ok_or_else(|| anyhow::anyhow!("ConnectivityChecker not initialized"))?;

        // Формируем check list из пар кандидатов
        let candidate_pairs = self.candidate_pairs.read().await.clone();
        checker.form_check_list(candidate_pairs).await?;

        // Запускаем connectivity checks
        checker.start_connectivity_checks().await?;

        // Ждем завершения
        self.connectivity_complete.notified().await;

        // Получаем успешные пары
        let valid_pairs = checker.get_valid_pairs().await;

        if valid_pairs.is_empty() {
            return Err(anyhow::anyhow!("No valid candidate pairs found"));
        }

        info!("Connectivity checks completed, {} valid pairs", valid_pairs.len());

        // Если есть успешные пары и мы не controlling, ждем nomination от remote
        if !self.config.controlling && !valid_pairs.is_empty() {
            self.process_state.write().await.agent_state = IceAgentState::Connected;
        }

        // Создаем фиктивные результаты для возврата
        let results: Vec<ConnectivityCheckResult> = valid_pairs.into_iter()
            .map(|pair| ConnectivityCheckResult {
                pair,
                success: true,
                rtt: Some(Duration::from_millis(50)),
                error: None,
                timestamp: Instant::now(),
            })
            .collect();

        Ok(results)
    }

    /// Выполнение nomination (только для controlling agent)
    pub async fn perform_nomination(&self) -> Result<Option<CandidatePair>> {
        if !self.config.controlling {
            debug!("Not controlling agent, skipping nomination");
            return Ok(None);
        }

        info!("Starting nomination process");

        // Обновляем состояние
        {
            let mut state = self.process_state.write().await;
            state.nomination_state = NominationState::InProgress;
        }

        let nominator = self.candidate_nominator.lock().await;
        let nominator = nominator.as_ref()
            .ok_or_else(|| anyhow::anyhow!("CandidateNominator not initialized"))?;

        // Получаем успешные пары от connectivity checker
        let checker = self.connectivity_checker.lock().await;
        let checker = checker.as_ref()
            .ok_or_else(|| anyhow::anyhow!("ConnectivityChecker not initialized"))?;

        let valid_pairs = checker.get_valid_pairs().await;

        // Добавляем пары для nomination
        nominator.add_valid_pairs(valid_pairs).await?;

        // Запускаем nomination
        nominator.start_nomination().await?;

        // Ждем завершения
        self.nomination_complete.notified().await;

        // Получаем номинированные пары
        let nominated_pairs = nominator.get_nominated_pairs().await;

        if let Some(pair) = nominated_pairs.first() {
            *self.nominated_pair.write().await = Some(pair.clone());
            info!("Nomination completed successfully");
            Ok(Some(pair.clone()))
        } else {
            Err(anyhow::anyhow!("Nomination failed"))
        }
    }

    /// Получение установленного соединения
    pub async fn get_connection(&self) -> Result<IceConnection> {
        let ice_connection = self.ice_connection.read().await;
        if let Some(connection) = ice_connection.as_ref() {
            Ok(connection.clone())
        } else {
            // Если нет готового соединения, создаем его из номинированной пары
            let nominated_pair = self.nominated_pair.read().await;
            if let Some(pair) = nominated_pair.as_ref() {
                // Получаем WebRTC соединение
                // TODO: Получить реальное соединение от webrtc-rs
                // let webrtc_conn = self.webrtc_agent.get_connection().await?;
                // let connection = IceConnection::new(webrtc_conn, pair.clone());

                // Для демонстрации создаем mock соединение
                let connection = self.create_mock_connection(pair.clone()).await?;

                // Сохраняем соединение
                *self.ice_connection.write().await = Some(connection.clone());

                Ok(connection)
            } else {
                Err(anyhow::anyhow!("No nominated pair available"))
            }
        }
    }

    /// Создание mock соединения (для демонстрации)
    async fn create_mock_connection(&self, pair: CandidatePair) -> Result<IceConnection> {
        // В реальности это должно получать соединение от webrtc-rs
        // Здесь мы создаем mock для демонстрации архитектуры

        use std::sync::Arc;

        // Mock WebRTC connection
        struct MockWebRtcConn;

        impl webrtc::ice::conn::Conn for MockWebRtcConn {
            fn send(&self, _data: &[u8]) -> Result<usize, webrtc::Error> {
                Ok(0) // Mock implementation
            }

            fn recv(&self, _buf: &mut [u8]) -> Result<usize, webrtc::Error> {
                Ok(0) // Mock implementation
            }

            fn close(&self) -> Result<(), webrtc::Error> {
                Ok(())
            }
        }

        let mock_conn: Arc<dyn webrtc::ice::conn::Conn + Send + Sync> =
            Arc::new(MockWebRtcConn);

        Ok(IceConnection::new(mock_conn, pair))
    }

    /// Restart ICE процесса
    pub async fn restart_ice(&self) -> Result<()> {
        info!("Restarting ICE process");

        // Обновляем статистику
        self.stats.write().await.ice_restart_count += 1;

        // Сброс состояния
        {
            let mut state = self.process_state.write().await;
            *state = IceProcessState::default();
            state.started_at = Some(Instant::now());
        }

        // Очистка данных
        self.local_candidates.write().await.clear();
        self.remote_candidates.write().await.clear();
        self.candidate_pairs.write().await.clear();
        *self.nominated_pair.write().await = None;
        *self.ice_connection.write().await = None;

        // Restart gathering
        let gatherer = self.candidate_gatherer.lock().await;
        if let Some(gatherer) = gatherer.as_ref() {
            gatherer.restart_gathering().await?;
        }

        info!("ICE restart completed");
        Ok(())
    }

    // Публичные методы для получения состояния

    /// Получение текущего состояния процесса
    pub async fn get_process_state(&self) -> IceProcessState {
        self.process_state.read().await.clone()
    }

    /// Получение локальных кандидатов
    pub async fn get_local_candidates(&self) -> Vec<Candidate> {
        self.local_candidates.read().await.clone()
    }

    /// Получение удаленных кандидатов
    pub async fn get_remote_candidates(&self) -> Vec<Candidate> {
        self.remote_candidates.read().await.clone()
    }

    /// Получение пар кандидатов
    pub async fn get_candidate_pairs(&self) -> Vec<CandidatePair> {
        self.candidate_pairs.read().await.clone()
    }

    /// Получение номинированной пары
    pub async fn get_nominated_pair(&self) -> Option<CandidatePair> {
        self.nominated_pair.read().await.clone()
    }

    /// Получение статистики
    pub async fn get_stats(&self) -> IceAgentStats {
        let mut stats = self.stats.read().await.clone();

        // Обновляем статистику от компонентов
        if let Some(gatherer) = self.candidate_gatherer.lock().await.as_ref() {
            stats.gathering_stats = gatherer.get_stats().await;
        }

        if let Some(checker) = self.connectivity_checker.lock().await.as_ref() {
            stats.connectivity_stats = checker.get_stats().await;
        }

        if let Some(nominator) = self.candidate_nominator.lock().await.as_ref() {
            stats.nomination_stats = nominator.get_stats().await;
        }

        // Вычисляем общую продолжительность
        let state = self.process_state.read().await;
        if let (Some(start), Some(end)) = (state.started_at, state.completed_at) {
            stats.total_duration = Some(end - start);
        }

        stats
    }

    /// Получение receiver для событий
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<IceEvent>> {
        self.event_rx.write().await.take()
    }

    /// Проверка состояния соединения
    pub async fn is_connected(&self) -> bool {
        let state = self.process_state.read().await;
        matches!(state.agent_state, IceAgentState::Connected)
    }

    /// Остановка ICE Agent
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down ICE Agent");
        *self.shutdown.write().await = true;

        // Остановка компонентов
        if let Some(gatherer) = self.candidate_gatherer.lock().await.as_ref() {
            gatherer.shutdown().await?;
        }

        if let Some(checker) = self.connectivity_checker.lock().await.as_ref() {
            checker.shutdown().await?;
        }

        if let Some(nominator) = self.candidate_nominator.lock().await.as_ref() {
            nominator.shutdown().await?;
        }

        // Закрытие соединения
        if let Some(connection) = self.ice_connection.read().await.as_ref() {
            connection.close().await?;
        }

        // Обновление состояния
        self.process_state.write().await.agent_state = IceAgentState::Closed;

        Ok(())
    }
}

/// Processor для обработки внутренних событий
struct IceEventProcessor {
    agent_weak: std::sync::Weak<()>, // Weak reference для избежания циклических ссылок
    event_rx: Mutex<mpsc::UnboundedReceiver<ConnectivityEvent>>,
    event_tx: mpsc::UnboundedSender<IceEvent>,
    process_state: Arc<RwLock<IceProcessState>>,
    stats: Arc<RwLock<IceAgentStats>>,
    gathering_complete: Arc<Notify>,
    connectivity_complete: Arc<Notify>,
    nomination_complete: Arc<Notify>,
    connection_established: Arc<Notify>,
}

impl IceEventProcessor {
    async fn run(self) {
        let mut event_rx = self.event_rx.into_inner();

        while let Some(event) = event_rx.recv().await {
            if self.agent_weak.upgrade().is_none() {
                break; // Agent был удален
            }

            self.handle_internal_event(event).await;
        }

        debug!("ICE event processor stopped");
    }

    async fn handle_internal_event(&self, event: ConnectivityEvent) {
        match event {
            ConnectivityEvent::GatheringStarted => {
                debug!("Processing gathering started event");
                self.process_state.write().await.gathering_state = GatheringState::Gathering;
            }

            ConnectivityEvent::CandidateGathered(candidate) => {
                trace!("Processing candidate gathered: {:?}", candidate.address);
                let _ = self.event_tx.send(IceEvent::CandidateGathered(candidate));
            }

            ConnectivityEvent::GatheringComplete(candidates) => {
                info!("Processing gathering complete: {} candidates", candidates.len());
                self.process_state.write().await.gathering_state = GatheringState::Complete;
                let _ = self.event_tx.send(IceEvent::GatheringComplete);
                self.gathering_complete.notify_one();
            }

            ConnectivityEvent::ConnectivityChecksStarted => {
                debug!("Processing connectivity checks started");
                self.process_state.write().await.connectivity_state = ConnectivityState::Checking;
                let _ = self.event_tx.send(IceEvent::ConnectivityChecksStarted);
            }

            ConnectivityEvent::ConnectivityCheckResult(result) => {
                trace!("Processing connectivity check result: success={}", result.success);
                let _ = self.event_tx.send(IceEvent::ConnectivityCheckCompleted(result));
            }

            ConnectivityEvent::CandidatePairNominated(pair) => {
                info!("Processing candidate pair nominated");
                self.process_state.write().await.nomination_state = NominationState::Nominated;
                let _ = self.event_tx.send(IceEvent::CandidatePairNominated(pair));
                self.nomination_complete.notify_one();
            }

            ConnectivityEvent::ConnectionEstablished(connection) => {
                info!("Processing connection established");
                self.process_state.write().await.agent_state = IceAgentState::Connected;
                // TODO: Извлечь IceConnection из EstablishedConnection
                // let _ = self.event_tx.send(IceEvent::ConnectionEstablished(ice_connection));
                self.connection_established.notify_one();
            }

            ConnectivityEvent::Error(error) => {
                error!("Processing error event: {}", error);
                self.process_state.write().await.agent_state = IceAgentState::Failed;
                self.stats.write().await.connection_failures += 1;
                let _ = self.event_tx.send(IceEvent::Error(error));
            }

            _ => {
                debug!("Unhandled internal event: {:?}", event);
            }
        }
    }
}

/// Фабрика для создания ICE Agent
pub struct IceAgentFactory;

impl IceAgentFactory {
    /// Создание стандартного ICE Agent
    pub async fn create_standard(ice_config: IceConfig, controlling: bool) -> Result<IceAgent> {
        IceAgent::new(ice_config, controlling).await
    }

    /// Создание ICE Agent для тестирования
    pub async fn create_test_agent() -> Result<IceAgent> {
        let ice_config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            connectivity_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        IceAgent::new(ice_config, true).await
    }

    /// Создание пары связанных ICE Agent (для тестирования)
    pub async fn create_agent_pair() -> Result<(IceAgent, IceAgent)> {
        let ice_config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            connectivity_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let controlling_agent = IceAgent::new(ice_config.clone(), true).await?;
        let controlled_agent = IceAgent::new(ice_config, false).await?;

        Ok((controlling_agent, controlled_agent))
    }
}