// src/connectivity/ice/gathering.rs
//! ICE Candidate Gathering Implementation
//! Comprehensive RFC 8445 compliant candidate gathering with webrtc-rs integration

use anyhow::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify, RwLock};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, trace, warn};

use webrtc::ice::{
    agent::Agent as WebRtcAgent,
    candidate::{Candidate as WebRtcCandidate, CandidateType as WebRtcCandidateType},
    state::GatheringState as WebRtcGatheringState,
};

use crate::connectivity::config::IceConfig;
use crate::connectivity::ice::utils::webrtc_candidate_to_candidate;
use crate::connectivity::{Candidate, CandidateAttributes, CandidateType, ConnectivityEvent};

/// Прогресс сбора кандидатов
#[derive(Debug, Clone)]
pub struct GatheringProgress {
    /// Текущее состояние сбора
    pub state: GatheringState,
    /// Количество собранных кандидатов по типам
    pub candidates_count: HashMap<CandidateType, usize>,
    /// Общее количество кандидатов
    pub total_candidates: usize,
    /// Время начала сбора
    pub started_at: Option<Instant>,
    /// Время завершения сбора
    pub completed_at: Option<Instant>,
    /// Ошибки во время сбора
    pub errors: Vec<String>,
}

/// Состояние процесса сбора кандидатов
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatheringState {
    /// Не начат
    New,
    /// Сбор в процессе
    Gathering,
    /// Сбор завершен
    Complete,
    /// Ошибка при сборе
    Failed,
}

impl From<WebRtcGatheringState> for GatheringState {
    fn from(state: WebRtcGatheringState) -> Self {
        match state {
            WebRtcGatheringState::New => Self::New,
            WebRtcGatheringState::Gathering => Self::Gathering,
            WebRtcGatheringState::Complete => Self::Complete,
        }
    }
}

/// Конфигурация для сбора кандидатов
#[derive(Debug, Clone)]
pub struct GatheringConfig {
    /// Максимальное время ожидания сбора
    pub gathering_timeout: Duration,
    /// Интервал между попытками
    pub retry_interval: Duration,
    /// Максимальное количество попыток для каждого сервера
    pub max_retries: u32,
    /// Собирать только IPv4 кандидатов
    pub ipv4_only: bool,
    /// Собирать только IPv6 кандидатов
    pub ipv6_only: bool,
    /// Приоритет локальных кандидатов
    pub host_candidate_priority: u32,
    /// Минимальный порт для поиска
    pub port_range_min: u16,
    /// Максимальный порт для поиска
    pub port_range_max: u16,
}

impl Default for GatheringConfig {
    fn default() -> Self {
        Self {
            gathering_timeout: Duration::from_secs(30),
            retry_interval: Duration::from_millis(500),
            max_retries: 3,
            ipv4_only: false,
            ipv6_only: false,
            host_candidate_priority: 126,
            port_range_min: 1024,
            port_range_max: 65535,
        }
    }
}

/// Статистика сбора кандидатов
#[derive(Debug, Clone, Default)]
pub struct GatheringStats {
    /// Время начала сбора
    pub started_at: Option<Instant>,
    /// Время завершения сбора
    pub completed_at: Option<Instant>,
    /// Количество попыток соединения с STUN серверами
    pub stun_requests_sent: u64,
    /// Количество успешных ответов от STUN серверов
    pub stun_responses_received: u64,
    /// Количество попыток соединения с TURN серверами
    pub turn_requests_sent: u64,
    /// Количество успешных ответов от TURN серверов
    pub turn_responses_received: u64,
    /// Количество собранных host кандидатов
    pub host_candidates_gathered: u64,
    /// Количество собранных server reflexive кандидатов
    pub srflx_candidates_gathered: u64,
    /// Количество собранных relay кандидатов
    pub relay_candidates_gathered: u64,
    /// Ошибки при сборе
    pub gathering_errors: Vec<String>,
}

impl GatheringStats {
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

    pub fn total_candidates(&self) -> u64 {
        self.host_candidates_gathered
            + self.srflx_candidates_gathered
            + self.relay_candidates_gathered
    }
}

/// Основной сборщик ICE кандидатов
pub struct CandidateGatherer {
    /// WebRTC ICE Agent
    webrtc_agent: Arc<WebRtcAgent>,
    /// Конфигурация сбора
    config: GatheringConfig,
    /// ICE конфигурация (STUN/TURN серверы)
    ice_config: IceConfig,
    /// Текущее состояние сбора
    state: Arc<RwLock<GatheringState>>,
    /// Прогресс сбора
    progress: Arc<RwLock<GatheringProgress>>,
    /// Собранные кандидаты
    gathered_candidates: Arc<RwLock<Vec<Candidate>>>,
    /// Статистика сбора
    stats: Arc<RwLock<GatheringStats>>,
    /// События для уведомления
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    /// Уведомление о завершении сбора
    gathering_complete: Arc<Notify>,
    /// Флаг остановки
    shutdown: Arc<RwLock<bool>>,
}

impl CandidateGatherer {
    /// Создание нового сборщика кандидатов
    pub fn new(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let config = GatheringConfig::default();

        let initial_progress = GatheringProgress {
            state: GatheringState::New,
            candidates_count: HashMap::new(),
            total_candidates: 0,
            started_at: None,
            completed_at: None,
            errors: Vec::new(),
        };

        Self {
            webrtc_agent,
            config,
            ice_config,
            state: Arc::new(RwLock::new(GatheringState::New)),
            progress: Arc::new(RwLock::new(initial_progress)),
            gathered_candidates: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(GatheringStats::new())),
            event_tx,
            gathering_complete: Arc::new(Notify::new()),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Создание с пользовательской конфигурацией
    pub fn with_config(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        gathering_config: GatheringConfig,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let mut gatherer = Self::new(webrtc_agent, ice_config, event_tx);
        gatherer.config = gathering_config;
        gatherer
    }

    /// Запуск процесса сбора кандидатов
    pub async fn start_gathering(&self) -> Result<()> {
        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("CandidateGatherer is shut down"));
        }

        let current_state = *self.state.read().await;
        if current_state != GatheringState::New {
            return Err(anyhow::anyhow!("Gathering already started or completed"));
        }

        info!("Starting ICE candidate gathering");

        // Обновляем состояние
        *self.state.write().await = GatheringState::Gathering;

        // Обновляем прогресс
        {
            let mut progress = self.progress.write().await;
            progress.state = GatheringState::Gathering;
            progress.started_at = Some(Instant::now());
        }

        // Обновляем статистику
        self.stats.write().await.started_at = Some(Instant::now());

        // Отправляем событие начала сбора
        let _ = self.event_tx.send(ConnectivityEvent::GatheringStarted);

        // Настраиваем обработчики событий webrtc-rs
        self.setup_event_handlers().await?;

        // Запускаем gathering процесс
        let gather_result = self.webrtc_agent.gather_candidates().await;

        match gather_result {
            Ok(()) => {
                debug!("WebRTC gathering started successfully");

                // Ждем завершения или таймаута
                self.wait_for_completion().await?;

                Ok(())
            }
            Err(e) => {
                error!("Failed to start WebRTC gathering: {}", e);
                self.handle_gathering_error(&e.to_string()).await;
                Err(anyhow::anyhow!("Failed to start gathering: {}", e))
            }
        }
    }

    /// Настройка обработчиков событий webrtc-rs
    async fn setup_event_handlers(&self) -> Result<()> {
        let gathered_candidates = Arc::clone(&self.gathered_candidates);
        let progress = Arc::clone(&self.progress);
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();
        let gathering_complete = Arc::clone(&self.gathering_complete);
        let state = Arc::clone(&self.state);

        // Обработчик новых кандидатов
        let event_tx_candidates = event_tx.clone();
        let gathered_candidates_clone = Arc::clone(&gathered_candidates);
        let progress_clone = Arc::clone(&progress);
        let stats_clone = Arc::clone(&stats);

        self.webrtc_agent
            .on_candidate(Box::new(move |webrtc_candidate| {
                let gathered_candidates = Arc::clone(&gathered_candidates_clone);
                let progress = Arc::clone(&progress_clone);
                let stats = Arc::clone(&stats_clone);
                let event_tx = event_tx_candidates.clone();

                Box::pin(async move {
                    if let Some(webrtc_candidate) = webrtc_candidate {
                        // Конвертируем webrtc кандидат в наш формат
                        match webrtc_candidate_to_candidate(webrtc_candidate.as_ref()) {
                            Ok(candidate) => {
                                trace!("Gathered candidate: {:?}", candidate);

                                // Добавляем к собранным кандидатам
                                gathered_candidates.write().await.push(candidate.clone());

                                // Обновляем прогресс
                                {
                                    let mut progress = progress.write().await;
                                    *progress
                                        .candidates_count
                                        .entry(candidate.candidate_type)
                                        .or_insert(0) += 1;
                                    progress.total_candidates += 1;
                                }

                                // Обновляем статистику
                                {
                                    let mut stats = stats.write().await;
                                    match candidate.candidate_type {
                                        CandidateType::Host => stats.host_candidates_gathered += 1,
                                        CandidateType::ServerReflexive => {
                                            stats.srflx_candidates_gathered += 1
                                        }
                                        CandidateType::Relay => {
                                            stats.relay_candidates_gathered += 1
                                        }
                                        _ => {}
                                    }
                                }

                                // Отправляем событие о новом кандидате
                                let _ =
                                    event_tx.send(ConnectivityEvent::CandidateGathered(candidate));
                            }
                            Err(e) => {
                                warn!("Failed to convert WebRTC candidate: {}", e);
                            }
                        }
                    } else {
                        // null candidate означает завершение gathering
                        debug!("Gathering completed (null candidate received)");
                        gathering_complete.notify_one();
                    }
                })
            }))
            .await;

        // Обработчик изменения состояния gathering
        let state_clone = Arc::clone(&state);
        let progress_clone = Arc::clone(&progress);
        let stats_clone = Arc::clone(&stats);
        let gathering_complete_clone = Arc::clone(&gathering_complete);
        let event_tx_state = event_tx.clone();

        self.webrtc_agent
            .on_gathering_state_change(Box::new(move |webrtc_state| {
                let state = Arc::clone(&state_clone);
                let progress = Arc::clone(&progress_clone);
                let stats = Arc::clone(&stats_clone);
                let gathering_complete = Arc::clone(&gathering_complete_clone);
                let event_tx = event_tx_state.clone();

                Box::pin(async move {
                    let new_state = GatheringState::from(webrtc_state);
                    debug!("Gathering state changed to: {:?}", new_state);

                    // Обновляем состояние
                    *state.write().await = new_state;

                    // Обновляем прогресс
                    {
                        let mut progress = progress.write().await;
                        progress.state = new_state;

                        if new_state == GatheringState::Complete {
                            progress.completed_at = Some(Instant::now());
                        }
                    }

                    // Обновляем статистику
                    if new_state == GatheringState::Complete {
                        stats.write().await.completed_at = Some(Instant::now());
                    }

                    // Если сбор завершен, уведомляем
                    if new_state == GatheringState::Complete {
                        let candidates = gathered_candidates.read().await.clone();
                        let _ = event_tx.send(ConnectivityEvent::GatheringComplete(candidates));
                        gathering_complete.notify_one();
                    }
                })
            }))
            .await;

        Ok(())
    }

    /// Ожидание завершения сбора с таймаутом
    async fn wait_for_completion(&self) -> Result<()> {
        let timeout_duration = self.config.gathering_timeout;

        match timeout(timeout_duration, self.gathering_complete.notified()).await {
            Ok(()) => {
                let state = *self.state.read().await;
                if state == GatheringState::Complete {
                    info!("ICE candidate gathering completed successfully");
                    let candidates = self.gathered_candidates.read().await;
                    info!("Gathered {} candidates", candidates.len());
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "Gathering completed with state: {:?}",
                        state
                    ))
                }
            }
            Err(_) => {
                warn!(
                    "ICE candidate gathering timed out after {:?}",
                    timeout_duration
                );
                self.handle_gathering_error("Gathering timeout").await;
                Err(anyhow::anyhow!("Gathering timeout"))
            }
        }
    }

    /// Обработка ошибок сбора
    async fn handle_gathering_error(&self, error: &str) {
        error!("Gathering error: {}", error);

        // Обновляем состояние
        *self.state.write().await = GatheringState::Failed;

        // Обновляем прогресс
        {
            let mut progress = self.progress.write().await;
            progress.state = GatheringState::Failed;
            progress.errors.push(error.to_string());
        }

        // Обновляем статистику
        self.stats
            .write()
            .await
            .gathering_errors
            .push(error.to_string());

        // Отправляем событие об ошибке
        let _ = self
            .event_tx
            .send(ConnectivityEvent::Error(error.to_string()));
    }

    /// Получение собранных кандидатов
    pub async fn get_candidates(&self) -> Vec<Candidate> {
        self.gathered_candidates.read().await.clone()
    }

    /// Получение кандидатов по типу
    pub async fn get_candidates_by_type(&self, candidate_type: CandidateType) -> Vec<Candidate> {
        self.gathered_candidates
            .read()
            .await
            .iter()
            .filter(|c| c.candidate_type == candidate_type)
            .cloned()
            .collect()
    }

    /// Получение текущего состояния
    pub async fn get_state(&self) -> GatheringState {
        *self.state.read().await
    }

    /// Получение прогресса сбора
    pub async fn get_progress(&self) -> GatheringProgress {
        self.progress.read().await.clone()
    }

    /// Получение статистики
    pub async fn get_stats(&self) -> GatheringStats {
        self.stats.read().await.clone()
    }

    /// Проверка завершения сбора
    pub async fn is_complete(&self) -> bool {
        *self.state.read().await == GatheringState::Complete
    }

    /// Проверка ошибок
    pub async fn has_failed(&self) -> bool {
        *self.state.read().await == GatheringState::Failed
    }

    /// Остановка процесса сбора
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down CandidateGatherer");
        *self.shutdown.write().await = true;

        // Если сбор еще не завершен, уведомляем о завершении
        if *self.state.read().await == GatheringState::Gathering {
            self.gathering_complete.notify_one();
        }

        Ok(())
    }

    /// Restart gathering процесса
    pub async fn restart_gathering(&self) -> Result<()> {
        info!("Restarting ICE candidate gathering");

        // Сброс состояния
        *self.state.write().await = GatheringState::New;
        self.gathered_candidates.write().await.clear();

        // Сброс прогресса
        {
            let mut progress = self.progress.write().await;
            progress.state = GatheringState::New;
            progress.candidates_count.clear();
            progress.total_candidates = 0;
            progress.started_at = None;
            progress.completed_at = None;
            progress.errors.clear();
        }

        // Сброс статистики
        *self.stats.write().await = GatheringStats::new();

        // Запускаем сбор заново
        self.start_gathering().await
    }

    /// Принудительное завершение gathering (для тестирования)
    #[cfg(test)]
    pub async fn force_complete(&self) {
        *self.state.write().await = GatheringState::Complete;
        self.gathering_complete.notify_one();
    }
}

/// Фабрика для создания CandidateGatherer
pub struct GathererFactory;

impl GathererFactory {
    /// Создание стандартного gatherer
    pub fn create_standard(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> CandidateGatherer {
        CandidateGatherer::new(webrtc_agent, ice_config, event_tx)
    }

    /// Создание gatherer для тестирования
    pub fn create_for_testing(
        webrtc_agent: Arc<WebRtcAgent>,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> CandidateGatherer {
        let ice_config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let gathering_config = GatheringConfig {
            gathering_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        CandidateGatherer::with_config(webrtc_agent, ice_config, gathering_config, event_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrtc::ice::agent::agent_config::AgentConfig;
    use webrtc::ice::network_type::NetworkType;

    /// Helper to create webrtc-rs agent for testing
    async fn create_test_webrtc_agent() -> Arc<WebRtcAgent> {
        let config = AgentConfig {
            network_types: vec![NetworkType::Udp4],
            ..Default::default()
        };

        Arc::new(
            WebRtcAgent::new(config)
                .await
                .expect("Failed to create test agent"),
        )
    }

    #[tokio::test]
    async fn test_gatherer_creation() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        let ice_config = IceConfig::default();
        let gatherer = GathererFactory::create_for_testing(webrtc_agent, ice_config, event_tx);

        assert_eq!(gatherer.get_state().await, GatheringState::New);
        assert_eq!(gatherer.get_candidates().await.len(), 0);
    }

    #[tokio::test]
    async fn test_gathering_config() {
        let config = GatheringConfig::default();

        assert_eq!(config.gathering_timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert!(!config.ipv4_only);
        assert!(!config.ipv6_only);
    }

    #[tokio::test]
    async fn test_gathering_progress() {
        let progress = GatheringProgress {
            state: GatheringState::New,
            candidates_count: HashMap::new(),
            total_candidates: 0,
            started_at: None,
            completed_at: None,
            errors: Vec::new(),
        };

        assert_eq!(progress.state, GatheringState::New);
        assert_eq!(progress.total_candidates, 0);
    }

    #[tokio::test]
    async fn test_state_conversion() {
        // Test conversion from WebRTC gathering state
        let webrtc_new = WebRtcGatheringState::New;
        let our_new: GatheringState = webrtc_new.into();
        assert_eq!(our_new, GatheringState::New);

        let webrtc_gathering = WebRtcGatheringState::Gathering;
        let our_gathering: GatheringState = webrtc_gathering.into();
        assert_eq!(our_gathering, GatheringState::Gathering);

        let webrtc_complete = WebRtcGatheringState::Complete;
        let our_complete: GatheringState = webrtc_complete.into();
        assert_eq!(our_complete, GatheringState::Complete);
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        let ice_config = IceConfig::default();
        let gatherer = CandidateGatherer::new(webrtc_agent, ice_config, event_tx);

        let result = gatherer.shutdown().await;
        assert!(result.is_ok());
    }
}
