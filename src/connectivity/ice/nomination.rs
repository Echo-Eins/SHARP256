// src/connectivity/ice/nomination.rs
//! ICE Nomination Implementation
//! RFC 8445 compliant nomination process with webrtc-rs integration

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify, RwLock};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use anyhow::Context;
use webrtc::ice::{agent::Agent as WebRtcAgent, candidate::Candidate as WebRtcCandidate};

use crate::connectivity::stun::{
    attributes::StunAttribute, transaction::TransactionId, StunClient, StunClientConfig,
    StunConfig, StunMessage, StunMessageType,
};

use crate::connectivity::{
    Candidate, CandidateAttributes, CandidatePair, CandidatePairState, CandidateType,
    ConnectivityEvent,
};

/// Convert webrtc-rs candidate to our Candidate format
fn webrtc_candidate_to_candidate(
    webrtc_candidate: &Arc<dyn WebRtcCandidate + Send + Sync>,
) -> Candidate {
    use std::net::SocketAddr;

    let candidate_type = match webrtc_candidate.candidate_type() {
        webrtc::ice::candidate::CandidateType::Host => CandidateType::Host,
        webrtc::ice::candidate::CandidateType::ServerReflexive => CandidateType::ServerReflexive,
        webrtc::ice::candidate::CandidateType::PeerReflexive => CandidateType::PeerReflexive,
        webrtc::ice::candidate::CandidateType::Relay => CandidateType::Relay,
        _ => CandidateType::Host, // Default fallback
    };

    let address = SocketAddr::new(
        webrtc_candidate
            .address()
            .parse()
            .unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
        webrtc_candidate.port(),
    );

    Candidate {
        foundation: webrtc_candidate.foundation().to_string(),
        priority: webrtc_candidate.priority(),
        address,
        candidate_type,
        base_address: address, // For simplicity, use same as address
        related_address: None,
        attributes: CandidateAttributes {
            component: webrtc_candidate.component() as u32,
            ..Default::default()
        },
    }
}

/// Результат nomination процесса
#[derive(Debug, Clone)]
pub struct NominationResult {
    /// Номинированная пара
    pub nominated_pair: CandidatePair,
    /// Время номинации
    pub nominated_at: Instant,
    /// Метод номинации (regular/aggressive)
    pub nomination_method: NominationMethod,
    /// Компонент (RTP/RTCP)
    pub component_id: u32,
    /// Успешность номинации
    pub success: bool,
    /// Причина неудачи (если есть)
    pub failure_reason: Option<String>,
}

/// Метод номинации
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NominationMethod {
    /// Regular nomination - ждем завершения checks, затем номинируем лучшую пару
    Regular,
    /// Aggressive nomination - номинируем сразу при первом успешном check
    Aggressive,
}

/// Состояние nomination процесса
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NominationState {
    /// Номинация не начата
    NotStarted,
    /// Номинация в процессе
    InProgress,
    /// Пара номинирована
    Nominated,
    /// Номинация завершена (для всех компонентов)
    Completed,
    /// Номинация неудачна
    Failed,
}

/// Конфигурация nomination процесса
#[derive(Debug, Clone)]
pub struct NominationConfig {
    /// Метод номинации
    pub method: NominationMethod,
    /// Задержка перед началом номинации (для regular method)
    pub nomination_delay: Duration,
    /// Максимальное время ожидания номинации
    pub nomination_timeout: Duration,
    /// Предпочтение relay кандидатов (для безопасности)
    pub prefer_relay_candidates: bool,
    /// Предпочтение IPv6 кандидатов
    pub prefer_ipv6: bool,
    /// Минимальное количество успешных пар перед номинацией
    pub min_successful_pairs: usize,
    /// Автоматическая re-nomination при изменении условий
    pub auto_renomination: bool,
}

impl Default for NominationConfig {
    fn default() -> Self {
        Self {
            method: NominationMethod::Regular,
            nomination_delay: Duration::from_millis(100),
            nomination_timeout: Duration::from_secs(15),
            prefer_relay_candidates: false,
            prefer_ipv6: false,
            min_successful_pairs: 1,
            auto_renomination: true,
        }
    }
}

/// Статистика nomination процесса
#[derive(Debug, Clone, Default)]
pub struct NominationStats {
    /// Время начала nomination
    pub started_at: Option<Instant>,
    /// Время завершения nomination
    pub completed_at: Option<Instant>,
    /// Количество nomination попыток
    pub nomination_attempts: u64,
    /// Количество успешных nominations
    pub successful_nominations: u64,
    /// Количество неудачных nominations
    pub failed_nominations: u64,
    /// Время до первой номинации
    pub time_to_nominate: Option<Duration>,
    /// Номинированные пары по компонентам
    pub nominated_pairs_by_component: HashMap<u32, CandidatePair>,
}

impl NominationStats {
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
        if self.nomination_attempts > 0 {
            self.successful_nominations as f64 / self.nomination_attempts as f64
        } else {
            0.0
        }
    }
}

/// Nomination entry для отслеживания состояния по компонентам
#[derive(Debug, Clone)]
struct NominationEntry {
    /// ID компонента
    component_id: u32,
    /// Текущее состояние
    state: NominationState,
    /// Кандидаты для номинации
    candidate_pairs: Vec<CandidatePair>,
    /// Номинированная пара
    nominated_pair: Option<CandidatePair>,
    /// Время номинации
    nominated_at: Option<Instant>,
    /// Количество попыток
    attempts: u32,
}

/// Основной processor для ICE nomination
pub struct CandidateNominator {
    /// WebRTC ICE Agent
    webrtc_agent: Arc<WebRtcAgent>,
    /// Конфигурация nomination
    config: NominationConfig,
    /// Controlling mode (только controlling agent может номинировать)
    controlling: bool,
    /// Entries по компонентам
    nomination_entries: Arc<RwLock<HashMap<u32, NominationEntry>>>,
    /// Общее состояние nomination
    state: Arc<RwLock<NominationState>>,
    /// Статистика
    stats: Arc<RwLock<NominationStats>>,
    /// События для уведомлений
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    /// Уведомление о завершении nomination
    nomination_complete: Arc<Notify>,
    /// Флаг остановки
    shutdown: Arc<RwLock<bool>>,
}

impl CandidateNominator {
    /// Создание нового nominator
    pub fn new(
        webrtc_agent: Arc<WebRtcAgent>,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let config = NominationConfig::default();

        Self {
            webrtc_agent,
            config,
            controlling,
            nomination_entries: Arc::new(RwLock::new(HashMap::new())),
            state: Arc::new(RwLock::new(NominationState::NotStarted)),
            stats: Arc::new(RwLock::new(NominationStats::new())),
            event_tx,
            nomination_complete: Arc::new(Notify::new()),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Создание с пользовательской конфигурацией
    pub fn with_config(
        webrtc_agent: Arc<WebRtcAgent>,
        controlling: bool,
        config: NominationConfig,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let mut nominator = Self::new(webrtc_agent, controlling, event_tx);
        nominator.config = config;
        nominator
    }

    /// Добавление успешных пар для номинации
    pub async fn add_valid_pairs(&self, pairs: Vec<CandidatePair>) -> Result<()> {
        if !self.controlling {
            debug!("Not controlling agent, ignoring valid pairs for nomination");
            return Ok(());
        }

        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("CandidateNominator is shut down"));
        }

        info!("Adding {} valid pairs for nomination", pairs.len());

        // Группируем пары по компонентам
        let mut pairs_by_component: HashMap<u32, Vec<CandidatePair>> = HashMap::new();
        for pair in pairs {
            let component_id = pair.local.attributes.component;
            pairs_by_component
                .entry(component_id)
                .or_insert_with(Vec::new)
                .push(pair);
        }

        // Добавляем entries для каждого компонента
        {
            let mut entries = self.nomination_entries.write().await;
            for (component_id, component_pairs) in pairs_by_component {
                let entry = entries
                    .entry(component_id)
                    .or_insert_with(|| NominationEntry {
                        component_id,
                        state: NominationState::NotStarted,
                        candidate_pairs: Vec::new(),
                        nominated_pair: None,
                        nominated_at: None,
                        attempts: 0,
                    });

                // Добавляем новые пары и сортируем по приоритету
                entry.candidate_pairs.extend(component_pairs);
                entry
                    .candidate_pairs
                    .sort_by(|a, b| b.priority.cmp(&a.priority));

                // Применяем дополнительные предпочтения
                if self.config.prefer_relay_candidates {
                    entry.candidate_pairs.sort_by_key(|pair| {
                        use crate::connectivity::CandidateType;
                        match (&pair.local.candidate_type, &pair.remote.candidate_type) {
                            (CandidateType::Relay, _) | (_, CandidateType::Relay) => 0,
                            _ => 1,
                        }
                    });
                }
            }
        }

        // Если aggressive nomination, начинаем номинацию сразу
        if self.config.method == NominationMethod::Aggressive {
            self.start_nomination().await?;
        }

        Ok(())
    }

    /// Запуск nomination процесса
    pub async fn start_nomination(&self) -> Result<()> {
        if !self.controlling {
            return Err(anyhow::anyhow!(
                "Only controlling agent can start nomination"
            ));
        }

        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("CandidateNominator is shut down"));
        }

        let current_state = *self.state.read().await;
        if current_state != NominationState::NotStarted {
            return Err(anyhow::anyhow!("Nomination already started"));
        }

        info!("Starting ICE nomination (method: {:?})", self.config.method);

        // Обновляем состояние
        *self.state.write().await = NominationState::InProgress;

        // Настраиваем обработчики событий webrtc-rs
        self.setup_event_handlers().await?;

        // Выполняем nomination в зависимости от метода
        match self.config.method {
            NominationMethod::Aggressive => {
                self.perform_aggressive_nomination().await?;
            }
            NominationMethod::Regular => {
                self.perform_regular_nomination().await?;
            }
        }

        Ok(())
    }

    /// Настройка обработчиков событий webrtc-rs
    async fn setup_event_handlers(&self) -> Result<()> {
        let stats = Arc::clone(&self.stats);
        let nomination_entries = Arc::clone(&self.nomination_entries);
        let event_tx = self.event_tx.clone();
        let nomination_complete = Arc::clone(&self.nomination_complete);
        let state = Arc::clone(&self.state);

        // Обработчик изменения выбранной пары
        let stats_clone = Arc::clone(&stats);
        let entries_clone = Arc::clone(&nomination_entries);
        let event_tx_clone = event_tx.clone();
        let nomination_complete_clone = Arc::clone(&nomination_complete);
        let state_clone = Arc::clone(&state);

        self.webrtc_agent
            .on_selected_candidate_pair_change(Box::new(move |webrtc_pair| {
                let stats = Arc::clone(&stats_clone);
                let entries = Arc::clone(&entries_clone);
                let event_tx = event_tx_clone.clone();
                let nomination_complete = Arc::clone(&nomination_complete_clone);
                let state = Arc::clone(&state_clone);

                Box::pin(async move {
                    if let Some(webrtc_pair) = webrtc_pair {
                        debug!("Selected candidate pair changed - nomination successful");

                        // Convert webrtc-rs candidate pair to our format
                        let local_candidate = webrtc_candidate_to_candidate(&webrtc_pair.local);
                        let remote_candidate = webrtc_candidate_to_candidate(&webrtc_pair.remote);
                        let component_id = webrtc_pair.local.component() as u32;

                        let nominated_pair = CandidatePair {
                            local: local_candidate,
                            remote: remote_candidate,
                            priority: (webrtc_pair.local.priority() as u64) << 32
                                | (webrtc_pair.remote.priority() as u64),
                            state: CandidatePairState::Succeeded,
                            nominated: true,
                            valid: true,
                            last_check: Some(Instant::now()),
                        };

                        // Update nomination entry for this component
                        {
                            let mut entries_guard = entries.write().await;
                            if let Some(entry) = entries_guard.get_mut(&component_id) {
                                entry.state = NominationState::Nominated;
                                entry.nominated_pair = Some(nominated_pair.clone());
                                entry.nominated_at = Some(Instant::now());
                            }
                        }

                        // Update statistics
                        {
                            let mut stats_guard = stats.write().await;
                            stats_guard.successful_nominations += 1;
                            stats_guard
                                .nominated_pairs_by_component
                                .insert(component_id, nominated_pair);
                            if let Some(started_at) = stats_guard.started_at {
                                stats_guard.time_to_nominate = Some(Instant::now() - started_at);
                            }
                        }

                        // Check if nomination completed for all components
                        let all_completed = {
                            let entries_guard = entries.read().await;
                            !entries_guard.is_empty()
                                && entries_guard
                                    .values()
                                    .all(|entry| entry.state == NominationState::Nominated)
                        };

                        if all_completed {
                            *state.write().await = NominationState::Completed;
                            stats.write().await.completed_at = Some(Instant::now());
                            nomination_complete.notify_one();
                        }
                    }
                })
            }))
            .await;

        Ok(())
    }

    /// Выполнение aggressive nomination
    async fn perform_aggressive_nomination(&self) -> Result<()> {
        debug!("Performing aggressive nomination");

        let entries_to_nominate = {
            let mut entries = self.nomination_entries.write().await;
            let mut to_nominate = Vec::new();

            for entry in entries.values_mut() {
                if entry.state == NominationState::NotStarted && !entry.candidate_pairs.is_empty() {
                    // В aggressive mode номинируем первую (лучшую) пару сразу
                    entry.state = NominationState::InProgress;
                    entry.attempts += 1;
                    to_nominate.push((entry.component_id, entry.candidate_pairs[0].clone()));
                }
            }

            to_nominate
        };

        // Номинируем пары
        for (component_id, pair) in entries_to_nominate {
            self.nominate_pair(component_id, pair).await?;
        }

        // Ждем завершения nomination с таймаутом
        let timeout_duration = self.config.nomination_timeout;
        match timeout(timeout_duration, self.nomination_complete.notified()).await {
            Ok(()) => {
                info!("Aggressive nomination completed successfully");
                Ok(())
            }
            Err(_) => {
                warn!(
                    "Aggressive nomination timed out after {:?}",
                    timeout_duration
                );
                self.handle_nomination_timeout().await;
                Err(anyhow::anyhow!("Nomination timeout"))
            }
        }
    }

    /// Выполнение regular nomination
    async fn perform_regular_nomination(&self) -> Result<()> {
        debug!("Performing regular nomination");

        // Ждем задержку перед началом nomination
        if self.config.nomination_delay > Duration::ZERO {
            sleep(self.config.nomination_delay).await;
        }

        // Проверяем, достаточно ли успешных пар
        let ready_for_nomination = {
            let entries = self.nomination_entries.read().await;
            entries
                .values()
                .all(|entry| entry.candidate_pairs.len() >= self.config.min_successful_pairs)
        };

        if !ready_for_nomination {
            warn!("Not enough successful pairs for regular nomination");
            return Err(anyhow::anyhow!("Insufficient pairs for nomination"));
        }

        let entries_to_nominate = {
            let mut entries = self.nomination_entries.write().await;
            let mut to_nominate = Vec::new();

            for entry in entries.values_mut() {
                if entry.state == NominationState::NotStarted && !entry.candidate_pairs.is_empty() {
                    // В regular mode выбираем лучшую пару после анализа всех
                    let best_pair = self.select_best_pair(&entry.candidate_pairs);
                    entry.state = NominationState::InProgress;
                    entry.attempts += 1;
                    to_nominate.push((entry.component_id, best_pair));
                }
            }

            to_nominate
        };

        // Номинируем выбранные пары
        for (component_id, pair) in entries_to_nominate {
            self.nominate_pair(component_id, pair).await?;
        }

        // Ждем завершения nomination с таймаутом
        let timeout_duration = self.config.nomination_timeout;
        match timeout(timeout_duration, self.nomination_complete.notified()).await {
            Ok(()) => {
                info!("Regular nomination completed successfully");
                Ok(())
            }
            Err(_) => {
                warn!("Regular nomination timed out after {:?}", timeout_duration);
                self.handle_nomination_timeout().await;
                Err(anyhow::anyhow!("Nomination timeout"))
            }
        }
    }

    /// Номинация конкретной пары
    ///
    /// Процесс nomination по RFC 8445:
    /// 1. Controlling agent отправляет STUN Binding Request с USE-CANDIDATE атрибутом
    /// 2. Controlled agent получает запрос и отмечает пару как nominated
    /// 3. После успешного response обе стороны используют эту пару
    ///
    /// webrtc-rs Agent обрабатывает USE-CANDIDATE внутренне при connectivity checks.
    /// Мы дополнительно измеряем RTT через наш STUN клиент для точной статистики.
    async fn nominate_pair(&self, component_id: u32, pair: CandidatePair) -> Result<()> {
        info!(
            "Nominating pair (component {}): {:?} -> {:?}",
            component_id, pair.local.address, pair.remote.address
        );

        // Update statistics
        self.stats.write().await.nomination_attempts += 1;

        // Check agent connection state
        let agent_state = self.webrtc_agent.get_connection_state().await;
        debug!(
            "WebRTC agent connection state before nomination: {:?}",
            agent_state
        );

        // Measure actual RTT to the peer using our STUN client
        // This provides accurate timing for statistics and logging
        let rtt = match self.measure_rtt_to_peer(&pair).await {
            Ok(measured_rtt) => {
                info!("Measured RTT to peer: {:?}", measured_rtt);
                measured_rtt
            }
            Err(e) => {
                debug!("Could not measure RTT: {} (using estimate)", e);
                Duration::from_millis(50) // Fallback estimate
            }
        };

        // webrtc-rs Agent handles USE-CANDIDATE internally:
        // - When Agent is in controlling mode
        // - It sends STUN Binding Request with USE-CANDIDATE attribute (0x0025)
        // - The on_selected_candidate_pair_change callback fires on success
        //
        // We track the pair and wait for the callback.

        // Send nomination event with RTT
        let _ = self.event_tx.send(ConnectivityEvent::NominationStarted {
            component_id,
            pair: pair.clone(),
        });

        debug!(
            "USE-CANDIDATE will be sent by webrtc-rs Agent for pair: {:?} -> {:?}",
            pair.local.address, pair.remote.address
        );

        // Log that nomination is in progress
        info!(
            "Nomination in progress (webrtc-rs handles USE-CANDIDATE), RTT={:?}",
            rtt
        );

        Ok(())
    }

    /// Measure RTT to peer using direct STUN binding request
    ///
    /// This sends a STUN Binding Request to the remote candidate's address
    /// to get an accurate RTT measurement for statistics.
    async fn measure_rtt_to_peer(&self, pair: &CandidatePair) -> Result<Duration> {
        use std::time::Instant;
        use tokio::net::UdpSocket;

        // Create a temporary socket for RTT measurement
        let local_addr = pair.local.address;
        let remote_addr = pair.remote.address;

        // Build STUN Binding Request
        let mut msg = StunMessage::new_binding_request();
        let request_bytes = msg.encode().context("Failed to encode STUN request")?;

        // Bind to local candidate address
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind socket for RTT measurement")?;

        let start = Instant::now();

        // Send request
        socket
            .send_to(&request_bytes, remote_addr)
            .await
            .context("Failed to send STUN request")?;

        // Wait for response with timeout
        let mut buf = vec![0u8; 548];
        let timeout_duration = Duration::from_secs(2);

        match tokio::time::timeout(timeout_duration, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                let rtt = start.elapsed();

                // Verify it's a valid STUN response
                if len >= 20 {
                    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    if magic == 0x2112A442 {
                        debug!("Received STUN response from {} (RTT: {:?})", from, rtt);
                        return Ok(rtt);
                    }
                }

                Err(anyhow::anyhow!("Invalid STUN response"))
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Socket error: {}", e)),
            Err(_) => Err(anyhow::anyhow!("RTT measurement timeout")),
        }
    }

    /// Обработка успешной номинации
    async fn handle_nomination_success(
        &self,
        component_id: u32,
        pair: CandidatePair,
    ) -> Result<()> {
        info!("Nomination successful for component {}", component_id);

        // Обновляем entry
        {
            let mut entries = self.nomination_entries.write().await;
            if let Some(entry) = entries.get_mut(&component_id) {
                entry.state = NominationState::Nominated;
                entry.nominated_pair = Some(pair.clone());
                entry.nominated_at = Some(Instant::now());
            }
        }

        // Обновляем статистику
        {
            let mut stats = self.stats.write().await;
            stats.successful_nominations += 1;
            stats
                .nominated_pairs_by_component
                .insert(component_id, pair.clone());
        }

        // Создаем результат номинации
        let result = NominationResult {
            nominated_pair: pair.clone(),
            nominated_at: Instant::now(),
            nomination_method: self.config.method,
            component_id,
            success: true,
            failure_reason: None,
        };

        // Отправляем событие номинации
        let _ = self
            .event_tx
            .send(ConnectivityEvent::CandidatePairNominated(pair));

        // Проверяем, завершена ли nomination для всех компонентов
        self.check_nomination_completion().await;

        Ok(())
    }

    /// Обработка неудачной номинации
    async fn handle_nomination_failure(
        &self,
        component_id: u32,
        pair: CandidatePair,
        reason: &str,
    ) -> Result<()> {
        warn!(
            "Nomination failed for component {}: {}",
            component_id, reason
        );

        // Обновляем entry
        {
            let mut entries = self.nomination_entries.write().await;
            if let Some(entry) = entries.get_mut(&component_id) {
                if entry.attempts < 3 {
                    // Максимум 3 попытки
                    entry.state = NominationState::NotStarted; // Попробуем другую пару
                } else {
                    entry.state = NominationState::Failed;
                }
            }
        }

        // Обновляем статистику
        self.stats.write().await.failed_nominations += 1;

        // Если есть другие пары, пробуем их
        self.retry_nomination_with_next_pair(component_id).await?;

        Ok(())
    }

    /// Повторная попытка номинации со следующей парой
    async fn retry_nomination_with_next_pair(&self, component_id: u32) -> Result<()> {
        let next_pair = {
            let mut entries = self.nomination_entries.write().await;
            if let Some(entry) = entries.get_mut(&component_id) {
                if entry.attempts < 3 && entry.candidate_pairs.len() > entry.attempts as usize {
                    let next_pair = entry.candidate_pairs[entry.attempts as usize].clone();
                    entry.state = NominationState::InProgress;
                    entry.attempts += 1;
                    Some(next_pair)
                } else {
                    entry.state = NominationState::Failed;
                    None
                }
            } else {
                None
            }
        };

        if let Some(pair) = next_pair {
            debug!(
                "Retrying nomination with next pair for component {}",
                component_id
            );
            self.nominate_pair(component_id, pair).await?;
        }

        Ok(())
    }

    /// Проверка завершения nomination для всех компонентов
    async fn check_nomination_completion(&self) {
        let (all_nominated, any_failed) = {
            let entries = self.nomination_entries.read().await;
            let all_nominated = !entries.is_empty()
                && entries
                    .values()
                    .all(|entry| entry.state == NominationState::Nominated);
            let any_failed = entries
                .values()
                .any(|entry| entry.state == NominationState::Failed);
            (all_nominated, any_failed)
        };

        if all_nominated {
            info!("Nomination completed for all components");
            *self.state.write().await = NominationState::Completed;
            self.stats.write().await.completed_at = Some(Instant::now());
            self.nomination_complete.notify_one();
        } else if any_failed {
            warn!("Nomination failed for some components");
            *self.state.write().await = NominationState::Failed;
            self.stats.write().await.completed_at = Some(Instant::now());
            self.nomination_complete.notify_one();
        }
    }

    /// Выбор лучшей пары для regular nomination
    fn select_best_pair(&self, pairs: &[CandidatePair]) -> CandidatePair {
        // Применяем алгоритм выбора лучшей пары
        // 1. Сортируем по приоритету
        // 2. Применяем предпочтения конфигурации

        let mut scored_pairs: Vec<(CandidatePair, f64)> = pairs
            .iter()
            .map(|pair| (pair.clone(), self.calculate_pair_score(pair)))
            .collect();

        scored_pairs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        scored_pairs[0].0.clone()
    }

    /// Расчет оценки пары для nomination
    fn calculate_pair_score(&self, pair: &CandidatePair) -> f64 {
        let mut score = pair.priority as f64;

        // Предпочтения relay кандидатов
        if self.config.prefer_relay_candidates {
            use crate::connectivity::CandidateType;
            match (&pair.local.candidate_type, &pair.remote.candidate_type) {
                (CandidateType::Relay, _) | (_, CandidateType::Relay) => score *= 1.2,
                _ => {}
            }
        }

        // Предпочтения IPv6
        if self.config.prefer_ipv6 {
            if pair.local.address.is_ipv6() && pair.remote.address.is_ipv6() {
                score *= 1.1;
            }
        }

        score
    }

    /// Обработка таймаута nomination
    async fn handle_nomination_timeout(&self) {
        warn!("Nomination process timed out");

        *self.state.write().await = NominationState::Failed;
        self.stats.write().await.completed_at = Some(Instant::now());

        let _ = self
            .event_tx
            .send(ConnectivityEvent::Error("Nomination timeout".to_string()));
    }

    // Публичные методы для получения состояния

    /// Получение текущего состояния
    pub async fn get_state(&self) -> NominationState {
        *self.state.read().await
    }

    /// Получение номинированных пар
    pub async fn get_nominated_pairs(&self) -> Vec<CandidatePair> {
        let entries = self.nomination_entries.read().await;
        entries
            .values()
            .filter_map(|entry| entry.nominated_pair.clone())
            .collect()
    }

    /// Получение номинированной пары для компонента
    pub async fn get_nominated_pair_for_component(
        &self,
        component_id: u32,
    ) -> Option<CandidatePair> {
        let entries = self.nomination_entries.read().await;
        entries.get(&component_id)?.nominated_pair.clone()
    }

    /// Получение статистики
    pub async fn get_stats(&self) -> NominationStats {
        self.stats.read().await.clone()
    }

    /// Проверка завершения nomination
    pub async fn is_completed(&self) -> bool {
        *self.state.read().await == NominationState::Completed
    }

    /// Проверка неудачи nomination
    pub async fn has_failed(&self) -> bool {
        *self.state.read().await == NominationState::Failed
    }

    /// Остановка nomination процесса
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down CandidateNominator");
        *self.shutdown.write().await = true;
        self.nomination_complete.notify_one();
        Ok(())
    }
}

/// Фабрика для создания CandidateNominator
pub struct NominatorFactory;

impl NominatorFactory {
    /// Создание стандартного nominator
    pub fn create_standard(
        webrtc_agent: Arc<WebRtcAgent>,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> CandidateNominator {
        CandidateNominator::new(webrtc_agent, controlling, event_tx)
    }

    /// Создание aggressive nominator
    pub fn create_aggressive(
        webrtc_agent: Arc<WebRtcAgent>,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> CandidateNominator {
        let config = NominationConfig {
            method: NominationMethod::Aggressive,
            nomination_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        CandidateNominator::with_config(webrtc_agent, controlling, config, event_tx)
    }

    /// Создание nominator для тестирования
    pub fn create_for_testing(
        webrtc_agent: Arc<WebRtcAgent>,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> CandidateNominator {
        let config = NominationConfig {
            method: NominationMethod::Regular,
            nomination_delay: Duration::from_millis(10),
            nomination_timeout: Duration::from_secs(5),
            min_successful_pairs: 1,
            ..Default::default()
        };

        CandidateNominator::with_config(webrtc_agent, controlling, config, event_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use webrtc::ice::agent::agent_config::AgentConfig;
    use webrtc::ice::network_type::NetworkType;

    /// Helper to create test candidate pair
    fn create_test_pair(component_id: u32, priority: u64) -> CandidatePair {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 10000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 20000);

        CandidatePair {
            local: Candidate {
                foundation: "1".to_string(),
                priority: (priority >> 32) as u32,
                address: local_addr,
                candidate_type: CandidateType::Host,
                base_address: local_addr,
                related_address: None,
                attributes: CandidateAttributes {
                    component: component_id,
                    ..Default::default()
                },
            },
            remote: Candidate {
                foundation: "2".to_string(),
                priority: (priority & 0xFFFFFFFF) as u32,
                address: remote_addr,
                candidate_type: CandidateType::Host,
                base_address: remote_addr,
                related_address: None,
                attributes: CandidateAttributes {
                    component: component_id,
                    ..Default::default()
                },
            },
            priority,
            state: CandidatePairState::Waiting,
            nominated: false,
            valid: true,
            last_check: None,
        }
    }

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
    async fn test_nominator_creation() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        let nominator = NominatorFactory::create_for_testing(webrtc_agent, true, event_tx);

        assert_eq!(nominator.get_state().await, NominationState::NotStarted);
        assert_eq!(nominator.get_nominated_pairs().await.len(), 0);
    }

    #[tokio::test]
    async fn test_nominator_config() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        // Test aggressive nominator
        let aggressive =
            NominatorFactory::create_aggressive(Arc::clone(&webrtc_agent), true, event_tx.clone());
        assert_eq!(aggressive.config.method, NominationMethod::Aggressive);

        // Test standard nominator
        let standard =
            NominatorFactory::create_standard(Arc::clone(&webrtc_agent), true, event_tx.clone());
        assert_eq!(standard.config.method, NominationMethod::Regular);
    }

    #[tokio::test]
    async fn test_add_valid_pairs() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        let nominator = CandidateNominator::new(webrtc_agent, true, event_tx);

        // Add pairs for component 1
        let pairs = vec![create_test_pair(1, 100), create_test_pair(1, 200)];

        let result = nominator.add_valid_pairs(pairs).await;
        assert!(result.is_ok());

        // Check entries were created
        let entries = nominator.nomination_entries.read().await;
        assert!(entries.contains_key(&1));
        assert_eq!(entries.get(&1).unwrap().candidate_pairs.len(), 2);
    }

    #[tokio::test]
    async fn test_controlled_agent_ignores_nomination() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        // Create as controlled agent (not controlling)
        let nominator = CandidateNominator::new(webrtc_agent, false, event_tx);

        let pairs = vec![create_test_pair(1, 100)];
        let result = nominator.add_valid_pairs(pairs).await;

        // Should succeed but entries should be empty (controlled agent ignores)
        assert!(result.is_ok());
        let entries = nominator.nomination_entries.read().await;
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_pair_score_calculation() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        let mut config = NominationConfig::default();
        config.prefer_relay_candidates = true;

        let nominator = CandidateNominator::with_config(webrtc_agent, true, config, event_tx);

        // Create host pair
        let host_pair = create_test_pair(1, 1000);

        // Create relay pair
        let mut relay_pair = create_test_pair(1, 1000);
        relay_pair.local.candidate_type = CandidateType::Relay;

        // Relay should score higher when prefer_relay_candidates is true
        let host_score = nominator.calculate_pair_score(&host_pair);
        let relay_score = nominator.calculate_pair_score(&relay_pair);

        assert!(relay_score > host_score, "Relay pair should score higher");
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let webrtc_agent = create_test_webrtc_agent().await;

        let nominator = CandidateNominator::new(webrtc_agent, true, event_tx);

        let result = nominator.shutdown().await;
        assert!(result.is_ok());

        // After shutdown, adding pairs should fail
        let pairs = vec![create_test_pair(1, 100)];
        let result = nominator.add_valid_pairs(pairs).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let stats = NominationStats::new();

        assert!(stats.started_at.is_some());
        assert_eq!(stats.nomination_attempts, 0);
        assert_eq!(stats.successful_nominations, 0);
        assert_eq!(stats.failed_nominations, 0);
        assert_eq!(stats.success_rate(), 0.0);
    }
}
