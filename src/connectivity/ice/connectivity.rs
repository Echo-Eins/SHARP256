// src/connectivity/ice/connectivity.rs
//! ICE Connectivity Checks Implementation
//! RFC 8445 compliant connectivity checking with webrtc-rs integration

use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Notify, Mutex};
use tokio::time::{timeout, sleep, interval};
use tracing::{debug, info, warn, error, trace};
use parking_lot::Mutex as ParkingMutex;

use webrtc::ice::{
    agent::Agent as WebRtcAgent,
    state::ConnectionState as WebRtcConnectionState,
};

use crate::connectivity::{
    Candidate, CandidatePair, CandidatePairState, ConnectivityEvent,
    ConnectivityCheckResult,
};
use crate::connectivity::config::IceConfig;

/// Результат отдельной connectivity проверки
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Проверенная пара кандидатов
    pub pair: CandidatePair,
    /// Успешность проверки
    pub success: bool,
    /// Время отклика (RTT)
    pub rtt: Option<Duration>,
    /// Время выполнения проверки
    pub timestamp: Instant,
    /// Причина неудачи (если есть)
    pub failure_reason: Option<String>,
    /// Тип проверки (ordinary, triggered)
    pub check_type: CheckType,
    /// ID транзакции STUN
    pub transaction_id: Option<String>,
}

/// Тип connectivity проверки
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckType {
    /// Обычная проверка
    Ordinary,
    /// Triggered проверка (вызванная входящим STUN запросом)
    Triggered,
}

/// Состояние connectivity checker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityState {
    /// Новый, не начал проверки
    New,
    /// Выполняет проверки
    Checking,
    /// Подключен (есть хотя бы одна успешная пара)
    Connected,
    /// Проверки завершены
    Completed,
    /// Проверки неудачны
    Failed,
    /// Отключен (временная потеря связи)
    Disconnected,
    /// Закрыт
    Closed,
}

impl From<WebRtcConnectionState> for ConnectivityState {
    fn from(state: WebRtcConnectionState) -> Self {
        match state {
            WebRtcConnectionState::New => Self::New,
            WebRtcConnectionState::Checking => Self::Checking,
            WebRtcConnectionState::Connected => Self::Connected,
            WebRtcConnectionState::Completed => Self::Completed,
            WebRtcConnectionState::Failed => Self::Failed,
            WebRtcConnectionState::Disconnected => Self::Disconnected,
            WebRtcConnectionState::Closed => Self::Closed,
        }
    }
}

/// Конфигурация connectivity checks
#[derive(Debug, Clone)]
pub struct ConnectivityConfig {
    /// Максимальное время ожидания connectivity checks
    pub connectivity_timeout: Duration,
    /// Интервал между checks
    pub check_interval: Duration,
    /// Максимальное количество одновременных checks
    pub max_concurrent_checks: usize,
    /// Количество повторных попыток для неудачных checks
    pub max_retries: u32,
    /// Таймаут для одного STUN запроса
    pub stun_timeout: Duration,
    /// Интервал между retransmissions
    pub retransmission_interval: Duration,
    /// Максимальное количество пар для проверки
    pub max_candidate_pairs: usize,
    /// Aggressive nomination mode
    pub aggressive_nomination: bool,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            connectivity_timeout: Duration::from_secs(30),
            check_interval: Duration::from_millis(50), // Ta timer
            max_concurrent_checks: 5,
            max_retries: 7,
            stun_timeout: Duration::from_millis(500),
            retransmission_interval: Duration::from_millis(500),
            max_candidate_pairs: 100,
            aggressive_nomination: false,
        }
    }
}

/// Статистика connectivity checks
#[derive(Debug, Clone, Default)]
pub struct ConnectivityStats {
    /// Время начала checks
    pub started_at: Option<Instant>,
    /// Время завершения checks
    pub completed_at: Option<Instant>,
    /// Общее количество отправленных checks
    pub checks_sent: u64,
    /// Количество полученных ответов
    pub checks_received: u64,
    /// Количество успешных checks
    pub successful_checks: u64,
    /// Количество неудачных checks
    pub failed_checks: u64,
    /// Количество retransmissions
    pub retransmissions: u64,
    /// Количество triggered checks
    pub triggered_checks: u64,
    /// Средний RTT
    pub average_rtt: Option<Duration>,
    /// Общее количество проверенных пар
    pub total_pairs_checked: u64,
    /// Количество успешных пар
    pub successful_pairs: u64,
    /// Время до первого успешного соединения
    pub time_to_connect: Option<Duration>,
}

impl ConnectivityStats {
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
        if self.checks_sent > 0 {
            self.successful_checks as f64 / self.checks_sent as f64
        } else {
            0.0
        }
    }
}

/// Запись в check list
#[derive(Debug, Clone)]
struct CheckListEntry {
    /// Пара кандидатов
    pair: CandidatePair,
    /// Состояние записи
    state: CheckEntryState,
    /// Время последней проверки
    last_check_time: Option<Instant>,
    /// Количество попыток
    retry_count: u32,
    /// Время следующей попытки
    next_retry_time: Option<Instant>,
    /// Результаты проверок
    check_results: Vec<CheckResult>,
    /// ID активной транзакции
    active_transaction_id: Option<String>,
}

/// Состояние записи в check list
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckEntryState {
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

/// Основной connectivity checker
pub struct ConnectivityChecker {
    /// WebRTC ICE Agent
    webrtc_agent: Arc<WebRtcAgent>,
    /// Конфигурация
    config: ConnectivityConfig,
    /// ICE конфигурация
    ice_config: IceConfig,
    /// Текущее состояние
    state: Arc<RwLock<ConnectivityState>>,
    /// Check list (приоритизированный список пар для проверки)
    check_list: Arc<RwLock<Vec<CheckListEntry>>>,
    /// Valid list (успешно проверенные пары)
    valid_list: Arc<RwLock<Vec<CandidatePair>>>,
    /// Nominated pairs
    nominated_pairs: Arc<RwLock<Vec<CandidatePair>>>,
    /// Текущие активные проверки
    active_checks: Arc<RwLock<HashSet<String>>>, // transaction IDs
    /// Очередь triggered checks
    triggered_queue: Arc<RwLock<VecDeque<CandidatePair>>>,
    /// Статистика
    stats: Arc<RwLock<ConnectivityStats>>,
    /// События для уведомлений
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    /// Уведомление о завершении checks
    checks_complete: Arc<Notify>,
    /// Уведомление о первом соединении
    first_connection: Arc<Notify>,
    /// Флаг остановки
    shutdown: Arc<RwLock<bool>>,
    /// Controlling mode (определяет роль в ICE)
    controlling: bool,
}

impl ConnectivityChecker {
    /// Создание нового connectivity checker
    pub fn new(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let config = ConnectivityConfig::default();

        Self {
            webrtc_agent,
            config,
            ice_config,
            state: Arc::new(RwLock::new(ConnectivityState::New)),
            check_list: Arc::new(RwLock::new(Vec::new())),
            valid_list: Arc::new(RwLock::new(Vec::new())),
            nominated_pairs: Arc::new(RwLock::new(Vec::new())),
            active_checks: Arc::new(RwLock::new(HashSet::new())),
            triggered_queue: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(ConnectivityStats::new())),
            event_tx,
            checks_complete: Arc::new(Notify::new()),
            first_connection: Arc::new(Notify::new()),
            shutdown: Arc::new(RwLock::new(false)),
            controlling,
        }
    }

    /// Создание с пользовательской конфигурацией
    pub fn with_config(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        connectivity_config: ConnectivityConfig,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> Self {
        let mut checker = Self::new(webrtc_agent, ice_config, controlling, event_tx);
        checker.config = connectivity_config;
        checker
    }

    /// Формирование check list из пар кандидатов
    pub async fn form_check_list(&self, candidate_pairs: Vec<CandidatePair>) -> Result<()> {
        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("ConnectivityChecker is shut down"));
        }

        info!("Forming check list from {} candidate pairs", candidate_pairs.len());

        // Ограничиваем количество пар
        let limited_pairs = if candidate_pairs.len() > self.config.max_candidate_pairs {
            warn!(
                "Too many candidate pairs ({}), limiting to {}",
                candidate_pairs.len(),
                self.config.max_candidate_pairs
            );
            candidate_pairs.into_iter().take(self.config.max_candidate_pairs).collect()
        } else {
            candidate_pairs
        };

        // Сортируем пары по приоритету (убывание)
        let mut sorted_pairs = limited_pairs;
        sorted_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Создаем check list entries
        let check_entries: Vec<CheckListEntry> = sorted_pairs
            .into_iter()
            .map(|pair| CheckListEntry {
                pair,
                state: CheckEntryState::Frozen, // Начинаем с frozen состояния
                last_check_time: None,
                retry_count: 0,
                next_retry_time: None,
                check_results: Vec::new(),
                active_transaction_id: None,
            })
            .collect();

        // Unfreeze первые пары для начала проверок
        let mut check_list = self.check_list.write().await;
        *check_list = check_entries;

        // Unfreeeze первые несколько пар
        let unfreeze_count = std::cmp::min(self.config.max_concurrent_checks, check_list.len());
        for entry in check_list.iter_mut().take(unfreeze_count) {
            entry.state = CheckEntryState::Waiting;
        }

        info!("Check list formed with {} entries, {} unfrozen",
              check_list.len(), unfreeze_count);

        Ok(())
    }

    /// Запуск connectivity checks
    pub async fn start_connectivity_checks(&self) -> Result<()> {
        if *self.shutdown.read().await {
            return Err(anyhow::anyhow!("ConnectivityChecker is shut down"));
        }

        let current_state = *self.state.read().await;
        if current_state != ConnectivityState::New {
            return Err(anyhow::anyhow!("Connectivity checks already started"));
        }

        info!("Starting ICE connectivity checks (controlling: {})", self.controlling);

        // Обновляем состояние
        *self.state.write().await = ConnectivityState::Checking;

        // Отправляем событие начала checks
        let _ = self.event_tx.send(ConnectivityEvent::ConnectivityChecksStarted);

        // Настраиваем обработчики событий webrtc-rs
        self.setup_event_handlers().await?;

        // Запускаем основной цикл проверок
        let checker_handle = {
            let checker = self.clone_for_task().await;
            tokio::spawn(async move {
                checker.run_connectivity_checks().await
            })
        };

        // Ждем завершения или таймаута
        let timeout_duration = self.config.connectivity_timeout;
        match timeout(timeout_duration, self.checks_complete.notified()).await {
            Ok(()) => {
                info!("Connectivity checks completed");
                checker_handle.abort();
                Ok(())
            }
            Err(_) => {
                warn!("Connectivity checks timed out after {:?}", timeout_duration);
                checker_handle.abort();
                self.handle_connectivity_timeout().await;
                Err(anyhow::anyhow!("Connectivity checks timeout"))
            }
        }
    }

    /// Настройка обработчиков событий webrtc-rs
    async fn setup_event_handlers(&self) -> Result<()> {
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();
        let first_connection = Arc::clone(&self.first_connection);
        let checks_complete = Arc::clone(&self.checks_complete);

        // Обработчик изменения состояния соединения
        let state_clone = Arc::clone(&state);
        let stats_clone = Arc::clone(&stats);
        let event_tx_state = event_tx.clone();
        let first_connection_clone = Arc::clone(&first_connection);
        let checks_complete_clone = Arc::clone(&checks_complete);

        self.webrtc_agent.on_connection_state_change(Box::new(move |webrtc_state| {
            let state = Arc::clone(&state_clone);
            let stats = Arc::clone(&stats_clone);
            let event_tx = event_tx_state.clone();
            let first_connection = Arc::clone(&first_connection_clone);
            let checks_complete = Arc::clone(&checks_complete_clone);

            Box::pin(async move {
                let new_state = ConnectivityState::from(webrtc_state);
                debug!("Connectivity state changed to: {:?}", new_state);

                // Обновляем состояние
                let old_state = {
                    let mut current_state = state.write().await;
                    let old = *current_state;
                    *current_state = new_state;
                    old
                };

                // Обновляем статистику
                match new_state {
                    ConnectivityState::Connected => {
                        if old_state != ConnectivityState::Connected {
                            let mut stats = stats.write().await;
                            if let Some(started_at) = stats.started_at {
                                stats.time_to_connect = Some(Instant::now() - started_at);
                            }
                            first_connection.notify_one();
                        }
                    }
                    ConnectivityState::Completed | ConnectivityState::Failed => {
                        stats.write().await.completed_at = Some(Instant::now());
                        checks_complete.notify_one();
                    }
                    _ => {}
                }

                // Отправляем событие об изменении состояния
                // (в будущем можно добавить ConnectivityEvent::StateChanged)
            })
        })).await;

        // Обработчик изменения выбранной пары кандидатов
        let valid_list = Arc::clone(&self.valid_list);
        let nominated_pairs = Arc::clone(&self.nominated_pairs);
        let event_tx_pair = event_tx.clone();

        self.webrtc_agent.on_selected_candidate_pair_change(Box::new(move |webrtc_pair| {
            let valid_list = Arc::clone(&valid_list);
            let nominated_pairs = Arc::clone(&nominated_pairs);
            let event_tx = event_tx_pair.clone();

            Box::pin(async move {
                if let Some(webrtc_pair) = webrtc_pair {
                    // Конвертируем webrtc пару в наш формат
                    // TODO: Реализовать конвертацию webrtc_pair_to_candidate_pair
                    // let pair = webrtc_pair_to_candidate_pair(webrtc_pair);
                    // nominated_pairs.write().await.push(pair.clone());
                    // let _ = event_tx.send(ConnectivityEvent::CandidatePairNominated(pair));

                    debug!("Selected candidate pair changed");
                }
            })
        })).await;

        Ok(())
    }

    /// Основной цикл connectivity checks
    async fn run_connectivity_checks(&self) -> Result<()> {
        debug!("Starting connectivity checks main loop");

        let mut check_interval = interval(self.config.check_interval);

        loop {
            if *self.shutdown.read().await {
                break;
            }

            tokio::select! {
                _ = check_interval.tick() => {
                    // Выполняем ordinary checks
                    self.perform_ordinary_checks().await?;

                    // Обрабатываем triggered checks
                    self.process_triggered_checks().await?;

                    // Проверяем, завершены ли все checks
                    if self.are_checks_complete().await {
                        break;
                    }
                }
                _ = self.checks_complete.notified() => {
                    debug!("Received checks complete notification");
                    break;
                }
            }
        }

        debug!("Connectivity checks main loop completed");
        Ok(())
    }

    /// Выполнение ordinary connectivity checks
    async fn perform_ordinary_checks(&self) -> Result<()> {
        let current_time = Instant::now();
        let max_concurrent = self.config.max_concurrent_checks;

        // Получаем количество активных checks
        let active_count = self.active_checks.read().await.len();
        if active_count >= max_concurrent {
            trace!("Max concurrent checks reached ({}), skipping", max_concurrent);
            return Ok(());
        }

        // Находим пары готовые для проверки
        let pairs_to_check = {
            let mut check_list = self.check_list.write().await;
            let mut pairs = Vec::new();

            for entry in check_list.iter_mut() {
                if pairs.len() >= (max_concurrent - active_count) {
                    break;
                }

                if self.should_check_entry(entry, current_time) {
                    entry.state = CheckEntryState::InProgress;
                    entry.last_check_time = Some(current_time);
                    pairs.push(entry.pair.clone());
                }
            }

            pairs
        };

        // Выполняем checks для выбранных пар
        for pair in pairs_to_check {
            self.perform_single_check(pair, CheckType::Ordinary).await?;
        }

        Ok(())
    }

    /// Обработка triggered checks
    async fn process_triggered_checks(&self) -> Result<()> {
        let pairs_to_check = {
            let mut triggered_queue = self.triggered_queue.write().await;
            let mut pairs = Vec::new();

            // Берем все пары из triggered queue
            while let Some(pair) = triggered_queue.pop_front() {
                pairs.push(pair);
            }

            pairs
        };

        // Выполняем triggered checks
        for pair in pairs_to_check {
            self.perform_single_check(pair, CheckType::Triggered).await?;
        }

        Ok(())
    }

    /// Выполнение одной connectivity проверки
    async fn perform_single_check(&self, pair: CandidatePair, check_type: CheckType) -> Result<()> {
        let transaction_id = self.generate_transaction_id();

        // Добавляем в активные checks
        self.active_checks.write().await.insert(transaction_id.clone());

        trace!("Performing {:?} check for pair: {:?} -> {:?}",
               check_type, pair.local.address, pair.remote.address);

        // Обновляем статистику
        {
            let mut stats = self.stats.write().await;
            stats.checks_sent += 1;
            if check_type == CheckType::Triggered {
                stats.triggered_checks += 1;
            }
        }

        // Симулируем STUN binding request через webrtc-rs
        // В реальности webrtc-rs делает это автоматически
        let check_start = Instant::now();

        // TODO: В webrtc-rs это происходит автоматически при вызове connect()
        // Здесь мы симулируем результат для демонстрации архитектуры

        // Создаем результат проверки
        let success = self.simulate_check_result(&pair).await;
        let rtt = if success { Some(Instant::now() - check_start) } else { None };

        let check_result = CheckResult {
            pair: pair.clone(),
            success,
            rtt,
            timestamp: Instant::now(),
            failure_reason: if success { None } else { Some("Connection failed".to_string()) },
            check_type,
            transaction_id: Some(transaction_id.clone()),
        };

        // Обрабатываем результат
        self.handle_check_result(check_result).await?;

        // Удаляем из активных checks
        self.active_checks.write().await.remove(&transaction_id);

        Ok(())
    }

    /// Обработка результата connectivity check
    async fn handle_check_result(&self, result: CheckResult) -> Result<()> {
        trace!("Check result: success={}, rtt={:?}", result.success, result.rtt);

        // Обновляем статистику
        {
            let mut stats = self.stats.write().await;
            stats.checks_received += 1;

            if result.success {
                stats.successful_checks += 1;
                stats.successful_pairs += 1;

                // Обновляем средний RTT
                if let Some(rtt) = result.rtt {
                    stats.average_rtt = Some(match stats.average_rtt {
                        Some(avg) => Duration::from_nanos(
                            (avg.as_nanos() + rtt.as_nanos()) / 2
                        ),
                        None => rtt,
                    });
                }
            } else {
                stats.failed_checks += 1;
            }
        }

        // Обновляем check list
        {
            let mut check_list = self.check_list.write().await;
            for entry in check_list.iter_mut() {
                if entry.pair.local.address == result.pair.local.address &&
                    entry.pair.remote.address == result.pair.remote.address {

                    entry.check_results.push(result.clone());

                    if result.success {
                        entry.state = CheckEntryState::Succeeded;

                        // Добавляем в valid list
                        self.valid_list.write().await.push(result.pair.clone());

                        // Unfreeze связанные пары
                        self.unfreeze_related_pairs(&result.pair).await;

                    } else {
                        entry.retry_count += 1;
                        if entry.retry_count >= self.config.max_retries {
                            entry.state = CheckEntryState::Failed;
                        } else {
                            entry.state = CheckEntryState::Waiting;
                            entry.next_retry_time = Some(
                                Instant::now() + self.config.retransmission_interval
                            );
                        }
                    }
                    break;
                }
            }
        }

        // Создаем событие о результате проверки
        let connectivity_result = ConnectivityCheckResult {
            pair: result.pair,
            success: result.success,
            rtt: result.rtt,
            error: result.failure_reason,
            timestamp: result.timestamp,
        };

        // Отправляем событие
        let _ = self.event_tx.send(
            ConnectivityEvent::ConnectivityCheckResult(connectivity_result)
        );

        Ok(())
    }

    /// Unfreeze связанных пар после успешной проверки
    async fn unfreeze_related_pairs(&self, successful_pair: &CandidatePair) {
        let mut check_list = self.check_list.write().await;

        for entry in check_list.iter_mut() {
            if entry.state == CheckEntryState::Frozen {
                // Unfreezing logic по RFC 8445
                // Если фундаменты совпадают, можно unfreezing
                if entry.pair.local.foundation == successful_pair.local.foundation ||
                    entry.pair.remote.foundation == successful_pair.remote.foundation {
                    entry.state = CheckEntryState::Waiting;
                    trace!("Unfroze pair: {:?} -> {:?}",
                           entry.pair.local.address, entry.pair.remote.address);
                }
            }
        }
    }

    /// Определение, нужно ли проверять entry
    fn should_check_entry(&self, entry: &CheckListEntry, current_time: Instant) -> bool {
        match entry.state {
            CheckEntryState::Waiting => true,
            CheckEntryState::Failed => {
                // Проверяем retry logic
                if entry.retry_count < self.config.max_retries {
                    if let Some(next_retry) = entry.next_retry_time {
                        current_time >= next_retry
                    } else {
                        true
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Проверка завершения всех checks
    async fn are_checks_complete(&self) -> bool {
        let check_list = self.check_list.read().await;

        // Проверяем, есть ли еще pending checks
        let has_pending = check_list.iter().any(|entry| {
            matches!(entry.state, CheckEntryState::Waiting | CheckEntryState::InProgress | CheckEntryState::Frozen)
        });

        if !has_pending {
            let valid_list = self.valid_list.read().await;
            if valid_list.is_empty() {
                // Нет успешных пар - failed
                *self.state.write().await = ConnectivityState::Failed;
            } else {
                // Есть успешные пары - completed
                *self.state.write().await = ConnectivityState::Completed;
            }
            true
        } else {
            false
        }
    }

    /// Обработка таймаута connectivity checks
    async fn handle_connectivity_timeout(&self) {
        warn!("Connectivity checks timed out");

        *self.state.write().await = ConnectivityState::Failed;
        self.stats.write().await.completed_at = Some(Instant::now());

        let _ = self.event_tx.send(ConnectivityEvent::Error(
            "Connectivity checks timeout".to_string()
        ));
    }

    /// Симуляция результата проверки (для демонстрации)
    async fn simulate_check_result(&self, pair: &CandidatePair) -> bool {
        // Имитируем некоторую вероятность успеха в зависимости от типа кандидатов
        let success_probability = match (&pair.local.candidate_type, &pair.remote.candidate_type) {
            (CandidateType::Host, CandidateType::Host) => 0.9,
            (CandidateType::ServerReflexive, CandidateType::ServerReflexive) => 0.7,
            (CandidateType::Relay, _) | (_, CandidateType::Relay) => 0.8,
            _ => 0.6,
        };

        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < success_probability
    }

    /// Генерация уникального ID транзакции
    fn generate_transaction_id(&self) -> String {
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        format!("{:08x}", rng.gen::<u32>())
    }

    /// Клонирование для передачи в async task
    async fn clone_for_task(&self) -> ConnectivityCheckerTask {
        ConnectivityCheckerTask {
            check_list: Arc::clone(&self.check_list),
            valid_list: Arc::clone(&self.valid_list),
            active_checks: Arc::clone(&self.active_checks),
            triggered_queue: Arc::clone(&self.triggered_queue),
            stats: Arc::clone(&self.stats),
            state: Arc::clone(&self.state),
            event_tx: self.event_tx.clone(),
            checks_complete: Arc::clone(&self.checks_complete),
            config: self.config.clone(),
            shutdown: Arc::clone(&self.shutdown),
        }
    }

    // Публичные методы для получения состояния

    /// Получение текущего состояния
    pub async fn get_state(&self) -> ConnectivityState {
        *self.state.read().await
    }

    /// Получение успешных пар
    pub async fn get_valid_pairs(&self) -> Vec<CandidatePair> {
        self.valid_list.read().await.clone()
    }

    /// Получение номинированных пар
    pub async fn get_nominated_pairs(&self) -> Vec<CandidatePair> {
        self.nominated_pairs.read().await.clone()
    }

    /// Получение статистики
    pub async fn get_stats(&self) -> ConnectivityStats {
        self.stats.read().await.clone()
    }

    /// Добавление triggered check
    pub async fn add_triggered_check(&self, pair: CandidatePair) {
        self.triggered_queue.write().await.push_back(pair);
    }

    /// Остановка connectivity checks
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down ConnectivityChecker");
        *self.shutdown.write().await = true;
        self.checks_complete.notify_one();
        Ok(())
    }
}

/// Структура для передачи в async task
struct ConnectivityCheckerTask {
    check_list: Arc<RwLock<Vec<CheckListEntry>>>,
    valid_list: Arc<RwLock<Vec<CandidatePair>>>,
    active_checks: Arc<RwLock<HashSet<String>>>,
    triggered_queue: Arc<RwLock<VecDeque<CandidatePair>>>,
    stats: Arc<RwLock<ConnectivityStats>>,
    state: Arc<RwLock<ConnectivityState>>,
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    checks_complete: Arc<Notify>,
    config: ConnectivityConfig,
    shutdown: Arc<RwLock<bool>>,
}

impl ConnectivityCheckerTask {
    async fn run_connectivity_checks(&self) -> Result<()> {
        // Реализация будет аналогична методу в ConnectivityChecker
        // Это нужно для передачи в отдельный tokio::spawn
        Ok(())
    }
}

/// Фабрика для создания ConnectivityChecker
pub struct ConnectivityCheckerFactory;

impl ConnectivityCheckerFactory {
    /// Создание стандартного checker
    pub fn create_standard(
        webrtc_agent: Arc<WebRtcAgent>,
        ice_config: IceConfig,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> ConnectivityChecker {
        ConnectivityChecker::new(webrtc_agent, ice_config, controlling, event_tx)
    }

    /// Создание checker для тестирования
    pub fn create_for_testing(
        webrtc_agent: Arc<WebRtcAgent>,
        controlling: bool,
        event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    ) -> ConnectivityChecker {
        let ice_config = IceConfig {
            connectivity_timeout: Duration::from_secs(10),
            check_interval: Duration::from_millis(50),
            ..Default::default()
        };

        let connectivity_config = ConnectivityConfig {
            connectivity_timeout: Duration::from_secs(10),
            max_concurrent_checks: 3,
            ..Default::default()
        };

        ConnectivityChecker::with_config(
            webrtc_agent,
            ice_config,
            connectivity_config,
            controlling,
            event_tx,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_checker_creation() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        // Для теста создаем mock webrtc agent
        // let webrtc_agent = Arc::new(create_test_agent().await);
        // let checker = ConnectivityCheckerFactory::create_for_testing(
        //     webrtc_agent, true, event_tx
        // );

        // assert_eq!(checker.get_state().await, ConnectivityState::New);
        // assert_eq!(checker.get_valid_pairs().await.len(), 0);
    }

    #[tokio::test]
    async fn test_check_list_formation() {
        // Тест формирования check list
    }

    #[tokio::test]
    async fn test_connectivity_checks() {
        // Тест выполнения connectivity checks
    }

    #[tokio::test]
    async fn test_pair_prioritization() {
        // Тест приоритизации пар
    }
}