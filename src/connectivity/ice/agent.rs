// src/connectivity/ice/agent.rs
//! ICE Agent реализация на основе webrtc-rs

#[cfg(feature = "webrtc-ice-stack")]
use anyhow::Result;
#[cfg(feature = "webrtc-ice-stack")]
use parking_lot::RwLock;
#[cfg(feature = "webrtc-ice-stack")]
use std::collections::HashMap;
#[cfg(feature = "webrtc-ice-stack")]
use std::sync::Arc;
#[cfg(feature = "webrtc-ice-stack")]
use std::time::{Duration, Instant};
#[cfg(feature = "webrtc-ice-stack")]
use tokio::sync::{mpsc, Notify};
#[cfg(feature = "webrtc-ice-stack")]
use tokio::time::{timeout, sleep};
#[cfg(feature = "webrtc-ice-stack")]
use tracing::{debug, info, warn, error, trace};

#[cfg(feature = "webrtc-ice-stack")]
use webrtc::ice::{
    agent::{Agent, AgentConfig},
    candidate::{Candidate as WebRtcCandidate, CandidateType},
    state::{ConnectionState, GatheringState},
    url::Url,
};

#[cfg(feature = "webrtc-ice-stack")]
use crate::connectivity::{
    Candidate, CandidatePair, CandidatePairState, ConnectivityCheckResult, ConnectivityEvent
};
#[cfg(feature = "webrtc-ice-stack")]
use crate::connectivity::config::IceConfig;
#[cfg(feature = "webrtc-ice-stack")]
use super::{IceConnection, IceAgentState, IceEvent};

/// Конфигурация ICE агента
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone)]
pub struct IceAgentConfig {
    pub ice_config: IceConfig,
    pub controlling: bool,
    pub local_ufrag: Option<String>,
    pub local_pwd: Option<String>,
    pub remote_ufrag: Option<String>,
    pub remote_pwd: Option<String>,
}

/// ICE Agent wrapper поверх webrtc-rs
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug)]
pub struct IceAgent {
    /// WebRTC ICE Agent
    webrtc_agent: Arc<Agent>,

    /// Конфигурация
    config: IceAgentConfig,

    /// Состояние агента
    state: Arc<RwLock<IceAgentState>>,

    /// Локальные кандидаты
    local_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Удаленные кандидаты
    remote_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Активные пары кандидатов
    candidate_pairs: Arc<RwLock<Vec<CandidatePair>>>,

    /// Номинированная пара
    nominated_pair: Arc<RwLock<Option<CandidatePair>>>,

    /// Установленное соединение
    ice_connection: Arc<RwLock<Option<IceConnection>>>,

    /// События ICE
    event_tx: mpsc::UnboundedSender<IceEvent>,
    event_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<IceEvent>>>>,

    /// Уведомления о завершении процессов
    gathering_complete: Arc<Notify>,
    connection_established: Arc<Notify>,

    /// Статистика connectivity checks
    connectivity_stats: Arc<RwLock<ConnectivityStats>>,
}

#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Default)]
struct ConnectivityStats {
    checks_sent: u64,
    checks_received: u64,
    checks_succeeded: u64,
    checks_failed: u64,
    total_rtt: Duration,
    rtt_samples: u64,
}

#[cfg(feature = "webrtc-ice-stack")]
impl ConnectivityStats {
    fn record_check_sent(&mut self) {
        self.checks_sent += 1;
    }

    fn record_check_received(&mut self) {
        self.checks_received += 1;
    }

    fn record_check_result(&mut self, success: bool, rtt: Option<Duration>) {
        if success {
            self.checks_succeeded += 1;
        } else {
            self.checks_failed += 1;
        }

        if let Some(rtt) = rtt {
            self.total_rtt += rtt;
            self.rtt_samples += 1;
        }
    }

    fn average_rtt(&self) -> Option<Duration> {
        if self.rtt_samples > 0 {
            Some(self.total_rtt / self.rtt_samples as u32)
        } else {
            None
        }
    }

    fn success_rate(&self) -> f32 {
        let total_checks = self.checks_succeeded + self.checks_failed;
        if total_checks > 0 {
            self.checks_succeeded as f32 / total_checks as f32
        } else {
            0.0
        }
    }
}

#[cfg(feature = "webrtc-ice-stack")]
impl IceAgent {
    /// Создание нового ICE агента
    pub async fn new(ice_config: IceConfig, controlling: bool) -> Result<Self> {
        info!("Creating ICE agent, controlling: {}", controlling);

        // Генерируем credentials если не предоставлены
        let local_ufrag = format!("sharp-{}", uuid::Uuid::new_v4().simple());
        let local_pwd = uuid::Uuid::new_v4().to_string();

        let config = IceAgentConfig {
            ice_config: ice_config.clone(),
            controlling,
            local_ufrag: Some(local_ufrag),
            local_pwd: Some(local_pwd),
            remote_ufrag: None,
            remote_pwd: None,
        };

        // Подготавливаем STUN/TURN серверы
        let mut urls = Vec::new();
        for stun_server in &ice_config.stun_servers {
            match Url::parse_url(stun_server) {
                Ok(url) => urls.push(url),
                Err(e) => warn!("Failed to parse STUN server URL {}: {}", stun_server, e),
            }
        }

        for turn_server in &ice_config.turn_servers {
            match Url::parse_url(&turn_server.url) {
                Ok(url) => urls.push(url),
                Err(e) => warn!("Failed to parse TURN server URL {}: {}", turn_server.url, e),
            }
        }

        // Создаем конфигурацию WebRTC агента
        let agent_config = AgentConfig {
            urls,
            is_controlling: controlling,
            candidate_types: {
                let mut types = Vec::new();
                if ice_config.enable_host_candidates {
                    types.push(CandidateType::Host);
                }
                if ice_config.enable_srflx_candidates {
                    types.push(CandidateType::ServerReflexive);
                }
                if ice_config.enable_relay_candidates {
                    types.push(CandidateType::Relay);
                }
                types
            },
            ..Default::default()
        };

        // Создаем WebRTC агент
        let webrtc_agent = Arc::new(Agent::new(agent_config).await?);

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let agent = Self {
            webrtc_agent,
            config,
            state: Arc::new(RwLock::new(IceAgentState::New)),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            remote_candidates: Arc::new(RwLock::new(Vec::new())),
            candidate_pairs: Arc::new(RwLock::new(Vec::new())),
            nominated_pair: Arc::new(RwLock::new(None)),
            ice_connection: Arc::new(RwLock::new(None)),
            event_tx,
            event_rx: Arc::new(RwLock::new(Some(event_rx))),
            gathering_complete: Arc::new(Notify::new()),
            connection_established: Arc::new(Notify::new()),
            connectivity_stats: Arc::new(RwLock::new(ConnectivityStats::default())),
        };

        // Настраиваем callbacks
        agent.setup_callbacks().await?;

        debug!("ICE agent created successfully");
        Ok(agent)
    }

    /// Настройка callbacks для WebRTC агента
    async fn setup_callbacks(&self) -> Result<()> {
        let state = self.state.clone();
        let state_clone = state.clone();

        // Connection state callback
        self.webrtc_agent.on_connection_state_change(Box::new(move |cs: ConnectionState| {
            let new_state = match cs {
                ConnectionState::New => IceAgentState::New,
                ConnectionState::Checking => IceAgentState::Connecting,
                ConnectionState::Connected => IceAgentState::Connected,
                ConnectionState::Completed => IceAgentState::Connected,
                ConnectionState::Disconnected => IceAgentState::Disconnected,
                ConnectionState::Failed => IceAgentState::Failed,
                ConnectionState::Closed => IceAgentState::Closed,
                _ => IceAgentState::New,
            };

            *state_clone.write() = new_state;
            debug!("ICE connection state changed: {:?}", new_state);

            Box::pin(async {})
        })).await;

        // Candidate callback
        let local_candidates = self.local_candidates.clone();
        let event_tx = self.event_tx.clone();
        let gathering_complete = self.gathering_complete.clone();

        self.webrtc_agent.on_candidate(Box::new(move |c: Option<Arc<dyn WebRtcCandidate + Send + Sync>>| {
            let local_candidates = local_candidates.clone();
            let event_tx = event_tx.clone();
            let gathering_complete = gathering_complete.clone();

            Box::pin(async move {
                if let Some(webrtc_candidate) = c {
                    // Конвертируем WebRTC кандидат в наш формат
                    match super::utils::webrtc_candidate_to_candidate(webrtc_candidate.as_ref()) {
                        Ok(candidate) => {
                            debug!("New ICE candidate gathered: {}", candidate.address);

                            local_candidates.write().push(candidate.clone());
                            let _ = event_tx.send(IceEvent::CandidateGathered(candidate));
                        }
                        Err(e) => {
                            warn!("Failed to convert WebRTC candidate: {}", e);
                        }
                    }
                } else {
                    // Null candidate означает завершение gathering
                    debug!("ICE candidate gathering completed");
                    gathering_complete.notify_waiters();
                    let _ = event_tx.send(IceEvent::GatheringComplete);
                }
            })
        })).await;

        Ok(())
    }

    /// Сбор локальных кандидатов с прогрессом
    pub async fn gather_candidates_with_progress(
        &self,
        progress_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Result<Vec<Candidate>> {
        info!("Starting ICE candidate gathering");
        *self.state.write() = IceAgentState::Gathering;

        // Запускаем gathering
        self.webrtc_agent.gather_candidates().await?;

        // Ждем завершения gathering с таймаутом
        let gathering_timeout = self.config.ice_config.gathering_timeout;

        match timeout(gathering_timeout, self.gathering_complete.notified()).await {
            Ok(_) => {
                let candidates = self.local_candidates.read().clone();
                info!("ICE candidate gathering completed, {} candidates found", candidates.len());

                // Отправляем прогресс
                for candidate in &candidates {
                    let _ = progress_tx.send(ConnectivityEvent::CandidateGathered(candidate.clone()));
                }

                Ok(candidates)
            }
            Err(_) => {
                warn!("ICE candidate gathering timed out");
                let candidates = self.local_candidates.read().clone();
                info!("Partial gathering result: {} candidates", candidates.len());
                Ok(candidates)
            }
        }
    }

    /// Добавление удаленного кандидата
    pub async fn add_remote_candidate(&self, candidate: Candidate) -> Result<()> {
        debug!("Adding remote ICE candidate: {}", candidate.address);

        // Конвертируем в WebRTC кандидат
        let webrtc_candidate = super::utils::candidate_to_webrtc_candidate(&candidate)?;

        // Добавляем в WebRTC агент
        self.webrtc_agent.add_remote_candidate(webrtc_candidate).await?;

        // Сохраняем в нашем списке
        self.remote_candidates.write().push(candidate.clone());

        // Создаем новые пары кандидатов
        self.create_candidate_pairs_for_new_remote(candidate).await;

        debug!("Remote ICE candidate added successfully");
        Ok(())
    }

    /// Создание пар кандидатов для нового remote кандидата
    async fn create_candidate_pairs_for_new_remote(&self, remote_candidate: Candidate) {
        let local_candidates = self.local_candidates.read().clone();
        let mut new_pairs = Vec::new();

        for local_candidate in local_candidates {
            if local_candidate.is_compatible_with(&remote_candidate) {
                let pair = CandidatePair::new(local_candidate, remote_candidate.clone());
                new_pairs.push(pair);
            }
        }

        if !new_pairs.is_empty() {
            // Сортируем по приоритету
            super::utils::prioritize_candidate_pairs(&mut new_pairs);

            // Добавляем к существующим парам
            self.candidate_pairs.write().extend(new_pairs);

            debug!("Created {} new candidate pairs", new_pairs.len());
        }
    }

    /// Выполнение connectivity checks
    pub async fn perform_connectivity_checks(&self) -> Result<Vec<ConnectivityCheckResult>> {
        info!("Starting ICE connectivity checks");
        *self.state.write() = IceAgentState::Connecting;

        let _ = self.event_tx.send(IceEvent::ConnectivityChecksStarted);

        let candidate_pairs = self.candidate_pairs.read().clone();
        let check_timeout = self.config.ice_config.connectivity_timeout;
        let check_interval = self.config.ice_config.check_interval;

        if candidate_pairs.is_empty() {
            warn!("No candidate pairs available for connectivity checks");
            return Ok(Vec::new());
        }

        info!("Performing connectivity checks on {} pairs", candidate_pairs.len());

        let mut check_results = Vec::new();
        let start_time = Instant::now();

        // Ограничиваем количество одновременных проверок
        let semaphore = Arc::new(tokio::sync::Semaphore::new(5));
        let mut tasks = Vec::new();

        for (index, pair) in candidate_pairs.iter().enumerate() {
            let pair = pair.clone();
            let webrtc_agent = self.webrtc_agent.clone();
            let event_tx = self.event_tx.clone();
            let stats = self.connectivity_stats.clone();
            let semaphore = semaphore.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                Self::perform_single_connectivity_check(
                    webrtc_agent,
                    pair,
                    index,
                    event_tx,
                    stats,
                ).await
            });

            tasks.push(task);

            // Небольшая задержка между запусками проверок
            if index % 5 == 4 {
                sleep(check_interval).await;
            }
        }

        // Собираем результаты с общим таймаутом
        let mut completed_tasks = 0;
        let mut successful_results = Vec::new();

        while completed_tasks < tasks.len() && start_time.elapsed() < check_timeout {
            for (i, task) in tasks.iter_mut().enumerate() {
                if task.is_finished() {
                    match task.await {
                        Ok(Ok(Some(result))) => {
                            successful_results.push(result.clone());
                            check_results.push(result);
                        }
                        Ok(Ok(None)) => {
                            // Проверка не удалась, но без ошибки
                        }
                        Ok(Err(e)) => {
                            debug!("Connectivity check {} failed: {}", i, e);
                        }
                        Err(e) => {
                            debug!("Connectivity check task {} panicked: {}", i, e);
                        }
                    }
                    completed_tasks += 1;
                }
            }

            // Если есть успешные результаты и мы в агрессивном режиме, можем остановиться
            if !successful_results.is_empty() &&
                self.config.ice_config.nomination_strategy == crate::connectivity::config::NominationStrategy::Aggressive {
                break;
            }

            sleep(Duration::from_millis(50)).await;
        }

        // Отменяем оставшиеся задачи
        for task in tasks {
            task.abort();
        }

        let stats = self.connectivity_stats.read();
        info!(
            "Connectivity checks completed: {}/{} successful, average RTT: {:?}",
            stats.checks_succeeded,
            stats.checks_sent,
            stats.average_rtt()
        );

        Ok(check_results)
    }

    /// Выполнение одной connectivity check
    async fn perform_single_connectivity_check(
        webrtc_agent: Arc<Agent>,
        pair: CandidatePair,
        check_index: usize,
        event_tx: mpsc::UnboundedSender<IceEvent>,
        stats: Arc<RwLock<ConnectivityStats>>,
    ) -> Result<Option<ConnectivityCheckResult>> {
        let start_time = Instant::now();

        trace!("Starting connectivity check {}: {} -> {}",
               check_index, pair.local.address, pair.remote.address);

        stats.write().record_check_sent();

        // Попытка установить соединение между кандидатами
        let local_addr = pair.local.address;
        let remote_addr = pair.remote.address;

        match timeout(
            Duration::from_secs(5),
            webrtc_agent.dial(local_addr, remote_addr)
        ).await {
            Ok(Ok(conn)) => {
                let rtt = start_time.elapsed();

                let result = ConnectivityCheckResult {
                    pair: pair.clone(),
                    success: true,
                    rtt: Some(rtt),
                    error: None,
                    timestamp: Instant::now(),
                };

                stats.write().record_check_result(true, Some(rtt));

                debug!(
                    "Connectivity check {} succeeded: {} -> {} (RTT: {:?})",
                    check_index, local_addr, remote_addr, rtt
                );

                let _ = event_tx.send(IceEvent::ConnectivityCheckCompleted(result.clone()));

                Ok(Some(result))
            }
            Ok(Err(e)) => {
                stats.write().record_check_result(false, None);

                trace!(
                    "Connectivity check {} failed: {} -> {} ({})",
                    check_index, local_addr, remote_addr, e
                );

                let result = ConnectivityCheckResult {
                    pair,
                    success: false,
                    rtt: None,
                    error: Some(e.to_string()),
                    timestamp: Instant::now(),
                };

                let _ = event_tx.send(IceEvent::ConnectivityCheckCompleted(result.clone()));

                Ok(Some(result))
            }
            Err(_) => {
                stats.write().record_check_result(false, None);

                trace!(
                    "Connectivity check {} timed out: {} -> {}",
                    check_index, local_addr, remote_addr
                );

                Ok(None)
            }
        }
    }

    /// Nomination пары кандидатов
    pub async fn nominate_pair(&self, pair: CandidatePair) -> Result<Option<CandidatePair>> {
        info!("Nominating candidate pair: {} -> {}", pair.local.address, pair.remote.address);

        // Обновляем состояние пары
        let mut updated_pair = pair.clone();
        updated_pair.nominated = true;
        updated_pair.update_state(CandidatePairState::Succeeded);

        // Сохраняем номинированную пару
        *self.nominated_pair.write() = Some(updated_pair.clone());

        // Пытаемся установить соединение
        match self.establish_connection_for_pair(&updated_pair).await {
            Ok(connection) => {
                *self.ice_connection.write() = Some(connection.clone());
                *self.state.write() = IceAgentState::Connected;

                let _ = self.event_tx.send(IceEvent::CandidatePairNominated(updated_pair.clone()));
                let _ = self.event_tx.send(IceEvent::ConnectionEstablished(connection));

                self.connection_established.notify_waiters();

                info!("ICE connection established successfully");
                Ok(Some(updated_pair))
            }
            Err(e) => {
                warn!("Failed to establish connection for nominated pair: {}", e);

                // Отменяем nomination
                *self.nominated_pair.write() = None;

                Err(e)
            }
        }
    }

    /// Установление соединения для пары кандидатов
    async fn establish_connection_for_pair(&self, pair: &CandidatePair) -> Result<IceConnection> {
        let local_addr = pair.local.address;
        let remote_addr = pair.remote.address;

        debug!("Establishing ICE connection: {} -> {}", local_addr, remote_addr);

        let conn = self.webrtc_agent.dial(local_addr, remote_addr).await?;

        Ok(IceConnection::new(conn, pair.clone()))
    }

    /// Получение установленного соединения
    pub async fn get_connection(&self) -> Result<Arc<dyn std::fmt::Debug + Send + Sync>> {
        if let Some(connection) = &*self.ice_connection.read() {
            // Возвращаем обертку для совместимости
            Ok(Arc::new(format!("IceConnection: {:?}", connection)) as Arc<dyn std::fmt::Debug + Send + Sync>)
        } else {
            Err(anyhow::anyhow!("No ICE connection established"))
        }
    }

    /// Получение состояния агента
    pub fn get_state(&self) -> IceAgentState {
        *self.state.read()
    }

    /// Подписка на события ICE
    pub async fn subscribe_events(&self) -> Option<mpsc::UnboundedReceiver<IceEvent>> {
        self.event_rx.write().take()
    }

    /// Получение номинированной пары
    pub fn get_nominated_pair(&self) -> Option<CandidatePair> {
        self.nominated_pair.read().clone()
    }

    /// Получение статистики connectivity checks
    pub fn get_connectivity_stats(&self) -> ConnectivityStats {
        self.connectivity_stats.read().clone()
    }

    /// Закрытие ICE агента
    pub async fn close(&self) -> Result<()> {
        info!("Closing ICE agent");

        *self.state.write() = IceAgentState::Closed;

        if let Some(connection) = &*self.ice_connection.read() {
            connection.close().await?;
        }

        self.webrtc_agent.close().await?;

        debug!("ICE agent closed successfully");
        Ok(())
    }
}

#[cfg(feature = "webrtc-ice-stack")]
impl Clone for IceAgent {
    fn clone(&self) -> Self {
        Self {
            webrtc_agent: self.webrtc_agent.clone(),
            config: self.config.clone(),
            state: self.state.clone(),
            local_candidates: self.local_candidates.clone(),
            remote_candidates: self.remote_candidates.clone(),
            candidate_pairs: self.candidate_pairs.clone(),
            nominated_pair: self.nominated_pair.clone(),
            ice_connection: self.ice_connection.clone(),
            event_tx: self.event_tx.clone(),
            event_rx: self.event_rx.clone(),
            gathering_complete: self.gathering_complete.clone(),
            connection_established: self.connection_established.clone(),
            connectivity_stats: self.connectivity_stats.clone(),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "webrtc-ice-stack")]
mod tests {
    use super::*;
    use crate::connectivity::config::IceConfig;

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let agent = IceAgent::new(config, true).await.unwrap();
        assert_eq!(agent.get_state(), IceAgentState::New);
    }

    #[tokio::test]
    async fn test_candidate_gathering() {
        let config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(10),
            enable_host_candidates: true,
            enable_srflx_candidates: false, // Отключаем для быстрого теста
            enable_relay_candidates: false,
            ..Default::default()
        };

        let agent = IceAgent::new(config, true).await.unwrap();
        let (progress_tx, _progress_rx) = mpsc::unbounded_channel();

        let candidates = agent.gather_candidates_with_progress(progress_tx).await.unwrap();

        // Должен быть хотя бы один host кандидат
        assert!(!candidates.is_empty());
        assert!(candidates.iter().any(|c| c.candidate_type == crate::connectivity::CandidateType::Host));
    }

    #[tokio::test]
    async fn test_remote_candidate_addition() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, true).await.unwrap();

        let remote_candidate = Candidate::host("192.168.1.100:5000".parse().unwrap());

        assert!(agent.add_remote_candidate(remote_candidate).await.is_ok());
        assert_eq!(agent.remote_candidates.read().len(), 1);
    }
}