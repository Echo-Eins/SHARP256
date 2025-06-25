// src/nat/ice_integration.rs
//! ICE интеграция с STUN/TURN менеджером
//!
//! Этот модуль обеспечивает интеграцию между ICE системой и STUN/TURN менеджером,
//! реализуя трейт IceNatManager для предоставления кандидатов для установления ICE соединений.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast, watch, mpsc, Mutex};
use tracing::{info, warn, debug, error, trace};
use futures::future::BoxFuture;
use serde::{Serialize, Deserialize};

// Используем существующие типы из модулей
use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::{
    IceNatManager, Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TransportProtocol, IceAgent, IceConfig, IceRole, IceState, IceEvent,
};
use crate::nat::stun_turn_manager::{
    StunTurnManager, StunTurnEvent, CandidateGatheringRequest,
    ConnectionQualityMetrics, TurnAllocationInfo,
};
use crate::nat::stun::NatBehavior;

/// ICE параметры для интеграции
#[derive(Debug, Clone)]
pub struct IceParameters {
    /// ICE username fragment
    pub ufrag: String,

    /// ICE password
    pub pwd: String,

    /// Компоненты для сбора кандидатов
    pub components: Vec<u32>,

    /// Конфигурация сбора
    pub gathering_config: IceGatheringConfig,

    /// Пороги качества
    pub quality_thresholds: QualityThresholds,
}

/// Конфигурация сбора ICE кандидатов
#[derive(Debug, Clone)]
pub struct IceGatheringConfig {
    /// Включить сбор host кандидатов
    pub gather_host: bool,

    /// Включить сбор server reflexive кандидатов
    pub gather_server_reflexive: bool,

    /// Включить сбор relay кандидатов
    pub gather_relay: bool,

    /// Таймаут сбора на компонент
    pub component_timeout: Duration,

    /// Общий таймаут сбора
    pub total_timeout: Duration,

    /// Максимальные кандидаты на компонент
    pub max_candidates_per_component: usize,

    /// Предпочесть IPv6 кандидаты
    pub prefer_ipv6: bool,

    /// Включить trickle ICE
    pub enable_trickle: bool,

    /// Параллельный сбор кандидатов
    pub parallel_gathering: bool,

    /// Максимальные параллельные сессии сбора
    pub max_parallel_sessions: usize,
}

/// Пороги качества для выбора кандидатов
#[derive(Debug, Clone)]
pub struct QualityThresholds {
    /// Минимальный RTT для приемлемых кандидатов (ms)
    pub max_acceptable_rtt: Duration,

    /// Максимальный уровень потери пакетов (0.0 to 1.0)
    pub max_packet_loss_rate: f64,

    /// Минимальная оценка пропускной способности (bytes/sec)
    pub min_bandwidth: u64,

    /// Порог оценки качества (0.0 to 1.0)
    pub min_quality_score: f64,
}

/// События ICE интеграции
#[derive(Debug, Clone)]
pub enum IceIntegrationEvent {
    /// Обнаружено поведение NAT
    NatBehaviorDetected {
        behavior: NatBehavior,
        confidence: f64,
    },

    /// Сессия сбора начата
    GatheringSessionStarted {
        session_id: String,
        component_id: u32,
    },

    /// Сессия сбора завершена
    GatheringSessionCompleted {
        session_id: String,
        component_id: u32,
        candidates_count: usize,
        duration: Duration,
    },

    /// Сессия сбора неудачна
    GatheringSessionFailed {
        session_id: String,
        component_id: u32,
        error: String,
    },

    /// Кандидат собран
    CandidateGathered {
        session_id: String,
        component_id: u32,
        candidate: Candidate,
        candidate_type: CandidateType,
    },

    /// Качество кандидата оценено
    CandidateQualityAssessed {
        candidate: Candidate,
        quality_metrics: ConnectionQualityMetrics,
    },

    /// Интеграция завершается
    IntegrationShutdown,
}

/// Статистика ICE интеграции
#[derive(Debug, Default)]
pub struct IceIntegrationStats {
    /// Общие сессии
    pub total_sessions: std::sync::atomic::AtomicU64,

    /// Активные сессии сбора
    pub active_sessions: std::sync::atomic::AtomicU64,

    /// Общие кандидаты собраны
    pub total_candidates: std::sync::atomic::AtomicU64,

    /// Кандидаты по типу
    pub host_candidates: std::sync::atomic::AtomicU64,
    pub server_reflexive_candidates: std::sync::atomic::AtomicU64,
    pub relay_candidates: std::sync::atomic::AtomicU64,

    /// Сбои сбора
    pub gathering_failures: std::sync::atomic::AtomicU64,

    /// Среднее время сбора (микросекунды)
    pub avg_gathering_time: std::sync::atomic::AtomicU64,

    /// Метрики качества
    pub avg_candidate_quality: std::sync::atomic::AtomicU64, // * 1000
}

/// Сессия сбора кандидатов
#[derive(Debug)]
pub struct GatheringSession {
    /// ID сессии
    pub session_id: String,

    /// Связанный сокет
    pub socket: Arc<UdpSocket>,

    /// Компоненты для сбора
    pub components: Vec<u32>,

    /// Время начала
    pub started_at: Instant,

    /// Состояние сбора
    pub state: GatheringState,

    /// Собранные кандидаты
    pub candidates: Vec<Candidate>,

    /// Отправитель отмены
    pub cancel_tx: Option<mpsc::Sender<()>>,
}

/// Состояние сбора кандидатов
#[derive(Debug, Clone, PartialEq)]
pub enum GatheringState {
    /// Инициализация
    Initializing,
    /// Сбор host кандидатов
    GatheringHost,
    /// Сбор server reflexive кандидатов
    GatheringServerReflexive,
    /// Сбор relay кандидатов
    GatheringRelay,
    /// Завершено
    Completed,
    /// Неудачно
    Failed(String),
    /// Отменено
    Cancelled,
}

/// SHARP ICE интеграция - реализует IceNatManager для ICE системы
pub struct Sharp3IceIntegration {
    /// STUN/TURN менеджер
    stun_turn_manager: Arc<StunTurnManager>,

    /// ICE параметры
    ice_params: Arc<RwLock<IceParameters>>,

    /// Активные сессии сбора кандидатов
    gathering_sessions: Arc<RwLock<HashMap<String, Arc<Mutex<GatheringSession>>>>>,

    /// Кэш собранных кандидатов
    candidates_cache: Arc<RwLock<HashMap<u32, Vec<Candidate>>>>,

    /// Кэш поведения NAT
    nat_behavior_cache: Arc<RwLock<Option<NatBehavior>>>,

    /// Подписчики событий
    event_subscribers: Arc<RwLock<Vec<broadcast::Sender<IceIntegrationEvent>>>>,

    /// Канал событий
    event_tx: broadcast::Sender<IceIntegrationEvent>,

    /// Статистика
    stats: Arc<IceIntegrationStats>,

    /// Флаг завершения работы
    shutdown: Arc<watch::Receiver<bool>>,
    shutdown_tx: watch::Sender<bool>,

    /// Фоновые задачи
    background_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Default for IceGatheringConfig {
    fn default() -> Self {
        Self {
            gather_host: true,
            gather_server_reflexive: true,
            gather_relay: true,
            component_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(30),
            max_candidates_per_component: 5,
            prefer_ipv6: false,
            enable_trickle: true,
            parallel_gathering: true,
            max_parallel_sessions: 4,
        }
    }
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            max_acceptable_rtt: Duration::from_millis(200),
            max_packet_loss_rate: 0.05, // 5%
            min_bandwidth: 100_000,     // 100 KB/s
            min_quality_score: 0.6,
        }
    }
}

impl Default for IceParameters {
    fn default() -> Self {
        Self {
            ufrag: generate_ufrag(),
            pwd: generate_password(),
            components: vec![1], // RTP компонент
            gathering_config: IceGatheringConfig::default(),
            quality_thresholds: QualityThresholds::default(),
        }
    }
}

impl Sharp3IceIntegration {
    /// Создать новую ICE интеграцию
    pub async fn new(
        stun_turn_manager: Arc<StunTurnManager>,
        ice_params: IceParameters,
    ) -> NatResult<Self> {
        info!("Создание SHARP ICE интеграции с {} компонентами", ice_params.components.len());

        // Создать каналы событий
        let (event_tx, _) = broadcast::channel(1000);

        // Создать каналы завершения работы
        let (shutdown_tx, shutdown) = watch::channel(false);

        let integration = Self {
            stun_turn_manager,
            ice_params: Arc::new(RwLock::new(ice_params)),
            gathering_sessions: Arc::new(RwLock::new(HashMap::new())),
            candidates_cache: Arc::new(RwLock::new(HashMap::new())),
            nat_behavior_cache: Arc::new(RwLock::new(None)),
            event_subscribers: Arc::new(RwLock::new(Vec::new())),
            event_tx,
            stats: Arc::new(IceIntegrationStats::default()),
            shutdown,
            shutdown_tx,
            background_tasks: Arc::new(Mutex::new(Vec::new())),
        };

        // Настроить перенаправление событий
        integration.setup_event_forwarding().await?;

        Ok(integration)
    }

    /// Настроить перенаправление событий от STUN/TURN менеджера
    async fn setup_event_forwarding(&self) -> NatResult<()> {
        let mut stun_turn_events = self.stun_turn_manager.subscribe();
        let nat_behavior_cache = self.nat_behavior_cache.clone();
        let event_tx = self.event_tx.clone();
        let shutdown = self.shutdown.clone();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    event_result = stun_turn_events.recv() => {
                        match event_result {
                            Ok(event) => {
                                match event {
                                    StunTurnEvent::NatBehaviorDiscovered { behavior, .. } => {
                                        *nat_behavior_cache.write().await = Some(behavior.clone());

                                        let ice_event = IceIntegrationEvent::NatBehaviorDetected {
                                            behavior,
                                            confidence: 0.8,
                                        };

                                        let _ = event_tx.send(ice_event);
                                    }
                                    StunTurnEvent::ConnectionQualityChanged { target, .. } => {
                                        trace!("Качество соединения обновлено для {}", target);
                                    }
                                    StunTurnEvent::Shutdown => {
                                        debug!("STUN/TURN менеджер завершается");
                                        break;
                                    }
                                    _ => {
                                        // Обрабатывать другие события по необходимости
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                warn!("Пропущены события STUN/TURN из-за отставания");
                                continue;
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!("Канал событий STUN/TURN закрыт");
                                break;
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        self.background_tasks.lock().await.push(task);
        Ok(())
    }

    /// Начать сессию сбора кандидатов
    pub async fn start_gathering_session(
        &self,
        session_id: String,
        socket: Arc<UdpSocket>,
    ) -> NatResult<()> {
        let ice_params = self.ice_params.read().await;
        let components = ice_params.components.clone();
        let gathering_config = ice_params.gathering_config.clone();
        drop(ice_params);

        info!("Начало ICE сессии сбора '{}' для компонентов: {:?}", session_id, components);

        // Создать канал отмены
        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);

        let session = Arc::new(Mutex::new(GatheringSession {
            session_id: session_id.clone(),
            socket: socket.clone(),
            components: components.clone(),
            started_at: Instant::now(),
            state: GatheringState::Initializing,
            candidates: Vec::new(),
            cancel_tx: Some(cancel_tx),
        }));

        // Зарегистрировать сессию
        self.gathering_sessions.write().await.insert(session_id.clone(), session.clone());
        self.stats.total_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.active_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Запустить сбор для каждого компонента
        for component_id in components {
            let _ = self.event_tx.send(IceIntegrationEvent::GatheringSessionStarted {
                session_id: session_id.clone(),
                component_id,
            });

            let session_clone = session.clone();
            let socket_clone = socket.clone();
            let gathering_config_clone = gathering_config.clone();
            let session_id_clone = session_id.clone();
            let event_tx = self.event_tx.clone();
            let stun_turn_manager = self.stun_turn_manager.clone();
            let stats = self.stats.clone();
            let candidates_cache = self.candidates_cache.clone();

            if gathering_config.parallel_gathering {
                // Параллельный сбор
                tokio::spawn(async move {
                    let result = Self::gather_candidates_for_component(
                        session_clone,
                        socket_clone,
                        component_id,
                        gathering_config_clone,
                        stun_turn_manager,
                        event_tx.clone(),
                        stats,
                        candidates_cache,
                        &mut cancel_rx,
                    ).await;

                    match result {
                        Ok(candidates) => {
                            let _ = event_tx.send(IceIntegrationEvent::GatheringSessionCompleted {
                                session_id: session_id_clone,
                                component_id,
                                candidates_count: candidates.len(),
                                duration: Instant::now().duration_since(
                                    session.lock().await.started_at
                                ),
                            });
                        }
                        Err(e) => {
                            error!("Сбор кандидатов неудачен для компонента {}: {}", component_id, e);
                            let _ = event_tx.send(IceIntegrationEvent::GatheringSessionFailed {
                                session_id: session_id_clone,
                                component_id,
                                error: e.to_string(),
                            });
                        }
                    }
                });
            }
        }

        Ok(())
    }

    /// Собрать кандидаты для конкретного компонента
    async fn gather_candidates_for_component(
        session: Arc<Mutex<GatheringSession>>,
        socket: Arc<UdpSocket>,
        component_id: u32,
        config: IceGatheringConfig,
        stun_turn_manager: Arc<StunTurnManager>,
        event_tx: broadcast::Sender<IceIntegrationEvent>,
        stats: Arc<IceIntegrationStats>,
        candidates_cache: Arc<RwLock<HashMap<u32, Vec<Candidate>>>>,
        cancel_rx: &mut mpsc::Receiver<()>,
    ) -> NatResult<Vec<Candidate>> {
        let mut candidates = Vec::new();
        let start_time = Instant::now();

        // Обновить состояние сессии
        {
            let mut session_guard = session.lock().await;
            session_guard.state = GatheringState::GatheringHost;
        }

        // 1. Собрать host кандидаты
        if config.gather_host {
            debug!("Сбор host кандидатов для компонента {}", component_id);

            if let Ok(local_addr) = socket.local_addr() {
                let host_candidate = Candidate {
                    address: CandidateAddress {
                        ip: local_addr.ip(),
                        port: local_addr.port(),
                        transport: TransportProtocol::Udp,
                    },
                    candidate_type: CandidateType::Host,
                    priority: Self::calculate_priority(CandidateType::Host, &local_addr.ip()),
                    foundation: format!("host{}{}", component_id, local_addr.port()),
                    component_id,
                    related_address: None,
                    tcp_type: None,
                    extensions: CandidateExtensions {
                        network_cost: Some(1),
                        generation: Some(0),
                    },
                };

                candidates.push(host_candidate.clone());
                stats.host_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let _ = event_tx.send(IceIntegrationEvent::CandidateGathered {
                    session_id: session.lock().await.session_id.clone(),
                    component_id,
                    candidate: host_candidate,
                    candidate_type: CandidateType::Host,
                });
            }
        }

        // Проверить отмену
        if let Ok(()) = cancel_rx.try_recv() {
            session.lock().await.state = GatheringState::Cancelled;
            return Ok(candidates);
        }

        // 2. Собрать server reflexive кандидаты
        if config.gather_server_reflexive {
            session.lock().await.state = GatheringState::GatheringServerReflexive;
            debug!("Сбор server reflexive кандидатов для компонента {}", component_id);

            match tokio::time::timeout(
                config.component_timeout,
                stun_turn_manager.get_server_reflexive_candidate(socket.clone(), component_id)
            ).await {
                Ok(Ok(Some(candidate))) => {
                    candidates.push(candidate.clone());
                    stats.server_reflexive_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let _ = event_tx.send(IceIntegrationEvent::CandidateGathered {
                        session_id: session.lock().await.session_id.clone(),
                        component_id,
                        candidate,
                        candidate_type: CandidateType::ServerReflexive,
                    });
                }
                Ok(Ok(None)) => {
                    debug!("Не удалось получить server reflexive кандидат для компонента {}", component_id);
                }
                Ok(Err(e)) => {
                    warn!("Ошибка получения server reflexive кандидата: {}", e);
                }
                Err(_) => {
                    warn!("Таймаут получения server reflexive кандидата для компонента {}", component_id);
                }
            }
        }

        // Проверить отмену
        if let Ok(()) = cancel_rx.try_recv() {
            session.lock().await.state = GatheringState::Cancelled;
            return Ok(candidates);
        }

        // 3. Собрать relay кандидаты
        if config.gather_relay {
            session.lock().await.state = GatheringState::GatheringRelay;
            debug!("Сбор relay кандидатов для компонента {}", component_id);

            match tokio::time::timeout(
                config.component_timeout,
                stun_turn_manager.get_relay_candidate(socket.clone(), component_id)
            ).await {
                Ok(Ok(Some(candidate))) => {
                    candidates.push(candidate.clone());
                    stats.relay_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let _ = event_tx.send(IceIntegrationEvent::CandidateGathered {
                        session_id: session.lock().await.session_id.clone(),
                        component_id,
                        candidate,
                        candidate_type: CandidateType::Relay,
                    });
                }
                Ok(Ok(None)) => {
                    debug!("Не удалось получить relay кандидат для компонента {}", component_id);
                }
                Ok(Err(e)) => {
                    warn!("Ошибка получения relay кандидата: {}", e);
                }
                Err(_) => {
                    warn!("Таймаут получения relay кандидата для компонента {}", component_id);
                }
            }
        }

        // Финализировать сессию
        {
            let mut session_guard = session.lock().await;
            session_guard.state = GatheringState::Completed;
            session_guard.candidates.extend(candidates.clone());
        }

        // Кэшировать кандидаты
        {
            let mut cache = candidates_cache.write().await;
            cache.entry(component_id).or_insert_with(Vec::new).extend(candidates.clone());
        }

        // Обновить статистику
        let gathering_time = start_time.elapsed();
        stats.total_candidates.fetch_add(candidates.len() as u64, std::sync::atomic::Ordering::Relaxed);
        stats.avg_gathering_time.store(
            gathering_time.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed
        );

        info!("Сбор кандидатов завершен для компонента {}: {} кандидатов за {}ms",
              component_id, candidates.len(), gathering_time.as_millis());

        Ok(candidates)
    }

    /// Вычислить приоритет кандидата
    fn calculate_priority(candidate_type: CandidateType, ip: &std::net::IpAddr) -> u32 {
        let type_preference = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };

        let local_preference = match ip {
            std::net::IpAddr::V4(_) => 65535,
            std::net::IpAddr::V6(_) => 65534,
        };

        (2_u32.pow(24) * type_preference) + (2_u32.pow(8) * local_preference) + 255
    }

    /// Получить кандидаты для компонента
    pub async fn get_candidates_for_component(&self, component_id: u32) -> Vec<Candidate> {
        self.candidates_cache.read().await
            .get(&component_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Подписаться на события интеграции
    pub async fn subscribe_to_events(&self) -> broadcast::Receiver<IceIntegrationEvent> {
        self.event_tx.subscribe()
    }

    /// Получить статистику
    pub fn get_stats(&self) -> &IceIntegrationStats {
        &self.stats
    }

    /// Получить кэшированное поведение NAT
    pub async fn get_nat_behavior(&self) -> Option<NatBehavior> {
        self.nat_behavior_cache.read().await.clone()
    }

    /// Завершить работу интеграции
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Завершение работы ICE интеграции");

        // Установить флаг завершения
        let _ = self.shutdown_tx.send(true);

        // Отправить событие завершения
        let _ = self.event_tx.send(IceIntegrationEvent::IntegrationShutdown);

        // Отменить все активные сессии
        let sessions: Vec<String> = self.gathering_sessions.read().await.keys().cloned().collect();
        for session_id in sessions {
            let _ = self.cancel_gathering_session(&session_id).await;
        }

        // Дождаться завершения фоновых задач
        let mut tasks = self.background_tasks.lock().await;
        while let Some(task) = tasks.pop() {
            let _ = task.await;
        }

        // Обновить статистику
        self.stats.active_sessions.store(0, std::sync::atomic::Ordering::Relaxed);

        info!("ICE интеграция завершена");
        Ok(())
    }

    /// Отменить сессию сбора
    async fn cancel_gathering_session(&self, session_id: &str) -> NatResult<()> {
        if let Some(session) = self.gathering_sessions.read().await.get(session_id) {
            let mut session_guard = session.lock().await;
            if let Some(cancel_tx) = session_guard.cancel_tx.take() {
                let _ = cancel_tx.send(()).await;
                session_guard.state = GatheringState::Cancelled;
                info!("Отменена сессия сбора: {}", session_id);
            }
        }
        Ok(())
    }
}

// Реализация трейта IceNatManager для интеграции с ICE системой
impl IceNatManager for Sharp3IceIntegration {
    /// Получить server reflexive кандидат для компонента
    fn get_server_reflexive(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>> {
        let manager = self.stun_turn_manager.clone();
        let stats = self.stats.clone();

        Box::pin(async move {
            let result = manager.get_server_reflexive_candidate(socket, component_id).await?;

            if result.is_some() {
                stats.server_reflexive_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats.total_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            Ok(result)
        })
    }

    /// Получить relay кандидат через TURN для компонента
    fn get_relay_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> BoxFuture<'static, NatResult<Option<Candidate>>> {
        let manager = self.stun_turn_manager.clone();
        let stats = self.stats.clone();

        Box::pin(async move {
            let result = manager.get_relay_candidate(socket, component_id).await?;

            if result.is_some() {
                stats.relay_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats.total_candidates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            Ok(result)
        })
    }
}

/// Обёртка, которая связывает IceAgent с Sharp3IceIntegration
pub struct IceSession {
    agent: Arc<crate::nat::ice::IceAgent>,
    integration: Arc<Sharp3IceIntegration>,
}

impl IceSession {
    /// Создать новую ICE сессию используя SHARP интеграцию
    pub async fn new(
        config: crate::nat::ice::IceConfig,
        stun_turn_manager: Arc<StunTurnManager>,
        ice_params: IceParameters,
    ) -> NatResult<Self> {
        let integration = Arc::new(Sharp3IceIntegration::new(stun_turn_manager, ice_params).await?);

        // Проверить ICE конфигурацию
        crate::nat::ice::validate_ice_config(&config)?;

        // Создать ICE агент
        let agent = Arc::new(crate::nat::ice::IceAgent::new(config).await?);

        Ok(Self { agent, integration })
    }

    /// Доступ к базовому ICE агенту
    pub fn agent(&self) -> Arc<crate::nat::ice::IceAgent> {
        self.agent.clone()
    }

    /// Доступ к ICE интеграции
    pub fn integration(&self) -> Arc<Sharp3IceIntegration> {
        self.integration.clone()
    }

    /// Запустить ICE обработку с указанной ролью
    pub async fn start(&self, role: IceRole) -> NatResult<()> {
        self.agent.start(role).await
    }

    /// Начать сбор кандидатов
    pub async fn start_gathering(&self, socket: Arc<UdpSocket>) -> NatResult<()> {
        let session_id = format!("session_{}", uuid::Uuid::new_v4());
        self.integration.start_gathering_session(session_id, socket).await
    }

    /// Получить собранные кандидаты для компонента
    pub async fn get_candidates(&self, component_id: u32) -> Vec<Candidate> {
        self.integration.get_candidates_for_component(component_id).await
    }

    /// Получить текущее состояние ICE
    pub async fn get_state(&self) -> crate::nat::ice::IceState {
        self.agent.get_state().await
    }

    /// Подписаться на события ICE
    pub fn subscribe_ice_events(&self) -> broadcast::Receiver<IceEvent> {
        self.agent.subscribe_events()
    }

    /// Подписаться на события интеграции
    pub async fn subscribe_integration_events(&self) -> broadcast::Receiver<IceIntegrationEvent> {
        self.integration.subscribe_to_events().await
    }

    /// Получить статистику интеграции
    pub fn get_integration_stats(&self) -> &IceIntegrationStats {
        self.integration.get_stats()
    }

    /// Получить статистику STUN/TURN
    pub fn get_stun_turn_stats(&self) -> &crate::nat::stun_turn_manager::StunTurnStats {
        self.integration.stun_turn_manager.get_stats()
    }

    /// Завершить сессию
    pub async fn shutdown(&self) -> NatResult<()> {
        // Завершить интеграцию
        self.integration.shutdown().await?;

        // Закрыть ICE агент
        self.agent.close().await?;

        Ok(())
    }
}

/// Фабричная функция для создания ICE сессии с SHARP интеграцией
pub async fn create_ice_session_with_sharp(
    ice_config: crate::nat::ice::IceConfig,
    stun_servers: Vec<String>,
    turn_servers: Vec<crate::nat::stun_turn_manager::TurnServerInfo>,
) -> NatResult<IceSession> {
    // Создать STUN/TURN менеджер
    let stun_turn_manager = Arc::new(
        crate::nat::stun_turn_manager::create_stun_turn_manager(
            stun_servers,
            turn_servers,
            false, // Не запускать интегрированный TURN сервер
        ).await?
    );

    // Создать ICE параметры
    let ice_params = IceParameters {
        ufrag: generate_ufrag(),
        pwd: generate_password(),
        components: ice_config.components.clone(),
        gathering_config: IceGatheringConfig::default(),
        quality_thresholds: QualityThresholds::default(),
    };

    // Создать ICE сессию
    IceSession::new(ice_config, stun_turn_manager, ice_params).await
}

/// Утилитарные функции для генерации ICE учетных данных
fn generate_ufrag() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

    let mut rng = rand::thread_rng();
    (0..4)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn generate_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

    let mut rng = rand::thread_rng();
    (0..22)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_integration_creation() {
        // Заглушка для теста - в реальности нужен рабочий StunTurnManager
        let stun_turn_manager = Arc::new(
            crate::nat::stun_turn_manager::create_stun_turn_manager(
                vec!["stun.l.google.com:19302".to_string()],
                vec![],
                false,
            ).await.unwrap()
        );

        let ice_params = IceParameters::default();
        let result = Sharp3IceIntegration::new(stun_turn_manager, ice_params).await;

        assert!(result.is_ok());
        if let Ok(integration) = result {
            assert_eq!(integration.get_stats().total_sessions.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn test_credential_generation() {
        let ufrag = generate_ufrag();
        let pwd = generate_password();

        assert_eq!(ufrag.len(), 4);
        assert_eq!(pwd.len(), 22);
        assert!(ufrag.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
        assert!(pwd.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    }

    #[test]
    fn test_priority_calculation() {
        let priority_host = Sharp3IceIntegration::calculate_priority(
            CandidateType::Host,
            &"192.168.1.1".parse().unwrap()
        );
        let priority_relay = Sharp3IceIntegration::calculate_priority(
            CandidateType::Relay,
            &"192.168.1.1".parse().unwrap()
        );

        assert!(priority_host > priority_relay);
    }
}