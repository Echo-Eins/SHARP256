// src/nat/ice/agent.rs
//! Исправленная реализация ICE Agent (RFC 8445)
//!
//! ICE Agent является основным координатором, который управляет сбором кандидатов,
//! проверками соединений и процессами номинации для установления peer-to-peer соединений.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast, mpsc, oneshot, watch};
use tokio::time::{interval, timeout, sleep};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};
use futures::future::BoxFuture;

use crate::nat::error::{NatError, NatResult};
use crate::nat::ice::{
    IceNatManager, Candidate, CandidateType, CandidateAddress, CandidateExtensions,
    TransportProtocol, TcpType
};

/// ICE Agent роль
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceRole {
    /// Controlling агент (инициирует номинацию)
    Controlling,
    /// Controlled агент (отвечает на номинацию)
    Controlled,
}

/// ICE Agent состояние
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceState {
    /// Сбор кандидатов
    Gathering,
    /// Соединение (выполнение проверок соединения)
    Connecting,
    /// Соединено (хотя бы один компонент соединен)
    Connected,
    /// Завершено (все компоненты соединены)
    Completed,
    /// Неудачно (невозможно установить соединение)
    Failed,
    /// Закрыто (агент был завершен)
    Closed,
}

impl Default for IceState {
    fn default() -> Self {
        IceState::Gathering
    }
}

/// ICE транспортная политика
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceTransportPolicy {
    /// Использовать все доступные транспорты
    All,
    /// Только relay транспорты (TURN)
    Relay,
    /// Нет ICE транспорта (отключить ICE)
    None,
}

/// Bundle политика
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundlePolicy {
    /// Balanced bundling
    Balanced,
    /// Максимальная совместимость
    MaxCompat,
    /// Максимальное bundling
    MaxBundle,
}

/// RTCP Mux политика
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RtcpMuxPolicy {
    /// Требовать RTCP mux
    Require,
    /// Договориться о RTCP mux
    Negotiate,
}

/// ICE конфигурация
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// Транспортная политика
    pub transport_policy: IceTransportPolicy,

    /// Компоненты для установления (обычно 1 для RTP, 2 для RTCP)
    pub components: Vec<u32>,

    /// Максимальное количество пар кандидатов на компонент
    pub max_pairs_per_component: usize,

    /// Таймаут соединения
    pub connectivity_timeout: Duration,

    /// Интервал keepalive
    pub keepalive_interval: Duration,

    /// Включить trickle ICE
    pub enable_trickle: bool,

    /// Включить consent freshness
    pub enable_consent_freshness: bool,

    /// Bundle политика
    pub bundle_policy: BundlePolicy,

    /// RTCP Mux политика
    pub rtcp_mux_policy: RtcpMuxPolicy,
}

/// ICE учетные данные
#[derive(Debug, Clone)]
pub struct IceCredentials {
    pub ufrag: String,
    pub pwd: String,
}

/// Пара кандидатов
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// ID пары
    pub pair_id: String,

    /// Локальный кандидат
    pub local_candidate: Candidate,

    /// Удаленный кандидат
    pub remote_candidate: Candidate,

    /// Состояние пары
    pub state: CandidatePairState,

    /// Приоритет пары
    pub priority: u64,

    /// Компонент ID
    pub component_id: u32,

    /// Время создания
    pub created_at: Instant,

    /// Последняя активность
    pub last_activity: Option<Instant>,

    /// Номинирована ли пара
    pub nominated: bool,
}

/// Состояние пары кандидатов
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePairState {
    /// Ожидание
    Waiting,
    /// В процессе
    InProgress,
    /// Успешно
    Succeeded,
    /// Неудачно
    Failed,
    /// Заморожено
    Frozen,
}

/// Список кандидатов
#[derive(Debug, Clone)]
pub struct CandidateList {
    pub candidates: Vec<Candidate>,
}

impl CandidateList {
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
        }
    }

    pub fn add(&mut self, candidate: Candidate) {
        self.candidates.push(candidate);
    }

    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

/// ICE Agent события
#[derive(Debug, Clone)]
pub enum IceEvent {
    /// Состояние изменилось
    StateChanged {
        old_state: IceState,
        new_state: IceState,
    },

    /// Новый кандидат обнаружен
    CandidateAdded {
        candidate: Candidate,
        component_id: u32,
    },

    /// Сбор кандидатов завершен
    GatheringCompleted {
        component_id: u32,
        candidate_count: usize,
    },

    /// Результат проверки соединения
    ConnectivityResult {
        pair_id: String,
        success: bool,
        rtt: Option<Duration>,
    },

    /// Компонент соединен
    ComponentConnected {
        component_id: u32,
        local_candidate: Candidate,
        remote_candidate: Candidate,
        selected_pair: CandidatePair,
    },

    /// Соединение установлено (все компоненты соединены)
    ConnectionEstablished {
        selected_pairs: HashMap<u32, CandidatePair>,
        establishment_time: Duration,
    },

    /// Соединение неудачно
    ConnectionFailed {
        reason: String,
    },

    /// Consent freshness потеряно
    ConsentLost {
        component_id: u32,
        pair_id: String,
    },

    /// ICE перезапуск инициирован
    IceRestart,
}

/// ICE Agent статистика
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IceStats {
    pub state: IceState,
    pub role: Option<IceRole>,
    pub gathering_time: Duration,
    pub connectivity_time: Duration,
    pub total_establishment_time: Duration,
    pub candidates_gathered: u32,
    pub pairs_checked: u32,
    pub successful_pairs: u32,
    pub nominated_pairs: u32,
    pub selected_pairs: HashMap<u32, String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// Соединение компонента
#[derive(Debug, Clone)]
pub struct ComponentConnection {
    pub component_id: u32,
    pub local_candidate: Candidate,
    pub remote_candidate: Candidate,
    pub selected_pair: CandidatePair,
    pub socket: Arc<UdpSocket>,
    pub established_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Команды агента для внешнего управления
#[derive(Debug)]
enum AgentCommand {
    /// Запустить ICE сбор и проверки соединения
    Start {
        role: IceRole,
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Добавить удаленный кандидат
    AddRemoteCandidate {
        candidate: Candidate,
        component_id: u32,
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Установить удаленные учетные данные
    SetRemoteCredentials {
        credentials: IceCredentials,
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Перезапустить ICE
    Restart {
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Закрыть агент
    Close {
        response: oneshot::Sender<NatResult<()>>,
    },

    /// Отправить данные на компонент
    SendData {
        component_id: u32,
        data: Vec<u8>,
        response: oneshot::Sender<NatResult<usize>>,
    },

    /// Получить состояние
    GetState {
        response: oneshot::Sender<IceState>,
    },
}

/// ICE Agent - основной оркестратор для ICE протокола
pub struct IceAgent {
    /// Конфигурация
    config: IceConfig,

    /// Текущее состояние
    state: Arc<RwLock<IceState>>,

    /// Текущая роль
    role: Arc<RwLock<Option<IceRole>>>,

    /// Локальные ICE учетные данные
    local_credentials: IceCredentials,

    /// Удаленные ICE учетные данные
    remote_credentials: Arc<RwLock<Option<IceCredentials>>>,

    /// NAT менеджер для получения кандидатов
    nat_manager: Option<Arc<dyn IceNatManager>>,

    /// Локальные кандидаты по компонентам
    local_candidates: Arc<RwLock<HashMap<u32, CandidateList>>>,

    /// Удаленные кандидаты по компонентам
    remote_candidates: Arc<RwLock<HashMap<u32, CandidateList>>>,

    /// Пары кандидатов по компонентам
    candidate_pairs: Arc<RwLock<HashMap<u32, Vec<CandidatePair>>>>,

    /// Соединения компонентов (установленные пары)
    connections: Arc<RwLock<HashMap<u32, ComponentConnection>>>,

    /// Вещатель событий
    event_sender: broadcast::Sender<IceEvent>,

    /// Канал команд для внешнего управления
    command_sender: mpsc::UnboundedSender<AgentCommand>,
    command_receiver: Arc<Mutex<mpsc::UnboundedReceiver<AgentCommand>>>,

    /// Сигнал завершения
    shutdown: Arc<watch::Receiver<bool>>,
    shutdown_tx: watch::Sender<bool>,

    /// Статистика
    stats: Arc<RwLock<IceStats>>,

    /// Время запуска для измерений времени
    start_time: Instant,

    /// Время начала сбора
    gathering_start_time: Arc<RwLock<Option<Instant>>>,

    /// Время начала соединения
    connectivity_start_time: Arc<RwLock<Option<Instant>>>,

    /// Фоновые задачи
    background_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            transport_policy: IceTransportPolicy::All,
            components: vec![1], // Только RTP по умолчанию
            max_pairs_per_component: 100,
            connectivity_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(25),
            enable_trickle: true,
            enable_consent_freshness: true,
            bundle_policy: BundlePolicy::Balanced,
            rtcp_mux_policy: RtcpMuxPolicy::Require,
        }
    }
}

impl IceAgent {
    /// Создать новый ICE агент
    pub async fn new(config: IceConfig) -> NatResult<Self> {
        let (event_sender, _) = broadcast::channel(1000);
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown) = watch::channel(false);

        // Генерировать локальные учетные данные
        let local_credentials = IceCredentials {
            ufrag: crate::nat::ice::utils::generate_ufrag(),
            pwd: crate::nat::ice::utils::generate_password(),
        };

        info!("Создание ICE агента с {} компонентами", config.components.len());

        let agent = Self {
            config,
            state: Arc::new(RwLock::new(IceState::Gathering)),
            role: Arc::new(RwLock::new(None)),
            local_credentials,
            remote_credentials: Arc::new(RwLock::new(None)),
            nat_manager: None,
            local_candidates: Arc::new(RwLock::new(HashMap::new())),
            remote_candidates: Arc::new(RwLock::new(HashMap::new())),
            candidate_pairs: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            command_sender,
            command_receiver: Arc::new(Mutex::new(command_receiver)),
            shutdown,
            shutdown_tx,
            stats: Arc::new(RwLock::new(IceStats::default())),
            start_time: Instant::now(),
            gathering_start_time: Arc::new(RwLock::new(None)),
            connectivity_start_time: Arc::new(RwLock::new(None)),
            background_tasks: Arc::new(Mutex::new(Vec::new())),
        };

        // Запустить обработчик команд
        agent.start_command_processor().await;

        info!("ICE агент создан успешно");
        Ok(agent)
    }

    /// Создать новый ICE агент с NAT менеджером
    pub async fn new_with_nat_manager(
        config: IceConfig,
        nat_manager: Arc<dyn IceNatManager>,
    ) -> NatResult<Self> {
        let mut agent = Self::new(config).await?;
        agent.nat_manager = Some(nat_manager);

        info!("ICE агент создан с NAT менеджером");
        Ok(agent)
    }

    /// Запустить ICE обработку с указанной ролью
    pub async fn start(&self, role: IceRole) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::Start { role, response: tx })
            .map_err(|_| NatError::Internal("Не удалось отправить команду start".to_string()))?;

        rx.await.map_err(|_| NatError::Internal("Не получен ответ на команду start".to_string()))?
    }

    /// Получить текущее состояние
    pub async fn get_state(&self) -> IceState {
        let (tx, rx) = oneshot::channel();

        if self.command_sender.send(AgentCommand::GetState { response: tx }).is_ok() {
            if let Ok(state) = rx.await {
                return state;
            }
        }

        *self.state.read().await
    }

    /// Подписаться на события
    pub fn subscribe_events(&self) -> broadcast::Receiver<IceEvent> {
        self.event_sender.subscribe()
    }

    /// Добавить удаленный кандидат
    pub async fn add_remote_candidate(&self, candidate: Candidate, component_id: u32) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::AddRemoteCandidate {
            candidate,
            component_id,
            response: tx,
        }).map_err(|_| NatError::Internal("Не удалось отправить команду add_remote_candidate".to_string()))?;

        rx.await.map_err(|_| NatError::Internal("Не получен ответ на команду add_remote_candidate".to_string()))?
    }

    /// Установить удаленные учетные данные
    pub async fn set_remote_credentials(&self, credentials: IceCredentials) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::SetRemoteCredentials {
            credentials,
            response: tx,
        }).map_err(|_| NatError::Internal("Не удалось отправить команду set_remote_credentials".to_string()))?;

        rx.await.map_err(|_| NatError::Internal("Не получен ответ на команду set_remote_credentials".to_string()))?
    }

    /// Отправить данные на компонент
    pub async fn send_data(&self, component_id: u32, data: Vec<u8>) -> NatResult<usize> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::SendData {
            component_id,
            data,
            response: tx,
        }).map_err(|_| NatError::Internal("Не удалось отправить команду send_data".to_string()))?;

        rx.await.map_err(|_| NatError::Internal("Не получен ответ на команду send_data".to_string()))?
    }

    /// Перезапустить ICE
    pub async fn restart(&self) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::Restart { response: tx })
            .map_err(|_| NatError::Internal("Не удалось отправить команду restart".to_string()))?;

        rx.await.map_err(|_| NatError::Internal("Не получен ответ на команду restart".to_string()))?
    }

    /// Закрыть агент
    pub async fn close(&self) -> NatResult<()> {
        let (tx, rx) = oneshot::channel();

        self.command_sender.send(AgentCommand::Close { response: tx })
            .map_err(|_| NatError::Internal("Не удалось отправить команду close".to_string()))?;

        rx.await.map_err(|_| NatError::Internal("Не получен ответ на команду close".to_string()))?
    }

    /// Получить локальные учетные данные
    pub fn get_local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Получить статистику
    pub async fn get_stats(&self) -> IceStats {
        self.stats.read().await.clone()
    }

    /// Получить локальные кандидаты для компонента
    pub async fn get_local_candidates(&self, component_id: u32) -> Vec<Candidate> {
        self.local_candidates.read().await
            .get(&component_id)
            .map(|list| list.candidates.clone())
            .unwrap_or_default()
    }

    /// Получить соединения компонентов
    pub async fn get_connections(&self) -> HashMap<u32, ComponentConnection> {
        self.connections.read().await.clone()
    }

    /// Запустить обработчик команд
    async fn start_command_processor(&self) {
        let command_receiver = self.command_receiver.clone();
        let state = self.state.clone();
        let role = self.role.clone();
        let local_candidates = self.local_candidates.clone();
        let remote_candidates = self.remote_candidates.clone();
        let remote_credentials = self.remote_credentials.clone();
        let event_sender = self.event_sender.clone();
        let nat_manager = self.nat_manager.clone();
        let config = self.config.clone();
        let shutdown = self.shutdown.clone();
        let shutdown_tx = self.shutdown_tx.clone();
        let stats = self.stats.clone();
        let gathering_start_time = self.gathering_start_time.clone();
        let connectivity_start_time = self.connectivity_start_time.clone();
        let connections = self.connections.clone();
        let background_tasks = self.background_tasks.clone();

        let task = tokio::spawn(async move {
            let mut receiver = command_receiver.lock().await;

            loop {
                tokio::select! {
                    command = receiver.recv() => {
                        match command {
                            Some(cmd) => {
                                Self::handle_command(
                                    cmd,
                                    &state,
                                    &role,
                                    &local_candidates,
                                    &remote_candidates,
                                    &remote_credentials,
                                    &event_sender,
                                    &nat_manager,
                                    &config,
                                    &stats,
                                    &gathering_start_time,
                                    &connectivity_start_time,
                                    &connections,
                                ).await;
                            }
                            None => {
                                debug!("Канал команд закрыт");
                                break;
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            debug!("Получен сигнал завершения");
                            break;
                        }
                    }
                }
            }

            // Завершить фоновые задачи
            let mut tasks = background_tasks.lock().await;
            for task in tasks.drain(..) {
                let _ = task.await;
            }
        });

        self.background_tasks.lock().await.push(task);
    }

    /// Обработать команду агента
    async fn handle_command(
        command: AgentCommand,
        state: &Arc<RwLock<IceState>>,
        role: &Arc<RwLock<Option<IceRole>>>,
        local_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        remote_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        remote_credentials: &Arc<RwLock<Option<IceCredentials>>>,
        event_sender: &broadcast::Sender<IceEvent>,
        nat_manager: &Option<Arc<dyn IceNatManager>>,
        config: &IceConfig,
        stats: &Arc<RwLock<IceStats>>,
        gathering_start_time: &Arc<RwLock<Option<Instant>>>,
        connectivity_start_time: &Arc<RwLock<Option<Instant>>>,
        connections: &Arc<RwLock<HashMap<u32, ComponentConnection>>>,
    ) {
        match command {
            AgentCommand::Start { role: agent_role, response } => {
                let result = Self::handle_start(
                    agent_role,
                    state,
                    role,
                    local_candidates,
                    event_sender,
                    nat_manager,
                    config,
                    stats,
                    gathering_start_time,
                    connectivity_start_time,
                ).await;
                let _ = response.send(result);
            }

            AgentCommand::GetState { response } => {
                let current_state = *state.read().await;
                let _ = response.send(current_state);
            }

            AgentCommand::AddRemoteCandidate { candidate, component_id, response } => {
                let result = Self::handle_add_remote_candidate(
                    candidate,
                    component_id,
                    remote_candidates,
                    event_sender,
                ).await;
                let _ = response.send(result);
            }

            AgentCommand::SetRemoteCredentials { credentials, response } => {
                *remote_credentials.write().await = Some(credentials);
                let _ = response.send(Ok(()));
            }

            AgentCommand::SendData { component_id, data, response } => {
                let result = Self::handle_send_data(component_id, data, connections).await;
                let _ = response.send(result);
            }

            AgentCommand::Restart { response } => {
                let result = Self::handle_restart(
                    state,
                    role,
                    local_candidates,
                    remote_candidates,
                    remote_credentials,
                    event_sender,
                ).await;
                let _ = response.send(result);
            }

            AgentCommand::Close { response } => {
                *state.write().await = IceState::Closed;
                let _ = event_sender.send(IceEvent::StateChanged {
                    old_state: *state.read().await,
                    new_state: IceState::Closed,
                });
                let _ = response.send(Ok(()));
            }
        }
    }

    /// Обработать команду start
    async fn handle_start(
        agent_role: IceRole,
        state: &Arc<RwLock<IceState>>,
        role: &Arc<RwLock<Option<IceRole>>>,
        local_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        event_sender: &broadcast::Sender<IceEvent>,
        nat_manager: &Option<Arc<dyn IceNatManager>>,
        config: &IceConfig,
        stats: &Arc<RwLock<IceStats>>,
        gathering_start_time: &Arc<RwLock<Option<Instant>>>,
        connectivity_start_time: &Arc<RwLock<Option<Instant>>>,
    ) -> NatResult<()> {
        info!("Запуск ICE агента с ролью {:?}", agent_role);

        // Установить роль
        *role.write().await = Some(agent_role);

        // Обновить состояние
        let old_state = *state.read().await;
        *state.write().await = IceState::Gathering;

        let _ = event_sender.send(IceEvent::StateChanged {
            old_state,
            new_state: IceState::Gathering,
        });

        // Установить время начала сбора
        *gathering_start_time.write().await = Some(Instant::now());

        // Обновить статистику
        {
            let mut stats_guard = stats.write().await;
            stats_guard.role = Some(agent_role);
            stats_guard.state = IceState::Gathering;
        }

        // Начать сбор кандидатов
        if let Some(nat_mgr) = nat_manager {
            Self::start_candidate_gathering(
                nat_mgr.clone(),
                config,
                local_candidates,
                event_sender,
                stats,
            ).await?;
        } else {
            // Собрать только host кандидаты
            Self::gather_host_candidates(config, local_candidates, event_sender, stats).await?;
        }

        Ok(())
    }

    /// Начать сбор кандидатов
    async fn start_candidate_gathering(
        nat_manager: Arc<dyn IceNatManager>,
        config: &IceConfig,
        local_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        event_sender: &broadcast::Sender<IceEvent>,
        stats: &Arc<RwLock<IceStats>>,
    ) -> NatResult<()> {
        info!("Начало сбора кандидатов для {} компонентов", config.components.len());

        for &component_id in &config.components {
            let socket = Arc::new(
                UdpSocket::bind("0.0.0.0:0").await
                    .map_err(|e| NatError::Network(format!("Не удалось создать сокет: {}", e)))?
            );

            // Собрать host кандидат
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

                // Добавить к локальным кандидатам
                {
                    let mut candidates = local_candidates.write().await;
                    candidates
                        .entry(component_id)
                        .or_insert_with(CandidateList::new)
                        .add(host_candidate.clone());
                }

                // Обновить статистику
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.candidates_gathered += 1;
                }

                // Отправить событие
                let _ = event_sender.send(IceEvent::CandidateAdded {
                    candidate: host_candidate,
                    component_id,
                });
            }

            // Собрать server reflexive кандидат
            if let Ok(Some(srflx_candidate)) = nat_manager
                .get_server_reflexive(socket.clone(), component_id)
                .await
            {
                // Добавить к локальным кандидатам
                {
                    let mut candidates = local_candidates.write().await;
                    candidates
                        .entry(component_id)
                        .or_insert_with(CandidateList::new)
                        .add(srflx_candidate.clone());
                }

                // Обновить статистику
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.candidates_gathered += 1;
                }

                // Отправить событие
                let _ = event_sender.send(IceEvent::CandidateAdded {
                    candidate: srflx_candidate,
                    component_id,
                });
            }

            // Собрать relay кандидат
            if let Ok(Some(relay_candidate)) = nat_manager
                .get_relay_candidate(socket.clone(), component_id)
                .await
            {
                // Добавить к локальным кандидатам
                {
                    let mut candidates = local_candidates.write().await;
                    candidates
                        .entry(component_id)
                        .or_insert_with(CandidateList::new)
                        .add(relay_candidate.clone());
                }

                // Обновить статистику
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.candidates_gathered += 1;
                }

                // Отправить событие
                let _ = event_sender.send(IceEvent::CandidateAdded {
                    candidate: relay_candidate,
                    component_id,
                });
            }

            // Отправить событие завершения сбора для компонента
            let candidate_count = local_candidates
                .read()
                .await
                .get(&component_id)
                .map(|list| list.len())
                .unwrap_or(0);

            let _ = event_sender.send(IceEvent::GatheringCompleted {
                component_id,
                candidate_count,
            });
        }

        info!("Сбор кандидатов завершен");
        Ok(())
    }

    /// Собрать только host кандидаты
    async fn gather_host_candidates(
        config: &IceConfig,
        local_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        event_sender: &broadcast::Sender<IceEvent>,
        stats: &Arc<RwLock<IceStats>>,
    ) -> NatResult<()> {
        info!("Сбор только host кандидатов");

        for &component_id in &config.components {
            let socket = UdpSocket::bind("0.0.0.0:0").await
                .map_err(|e| NatError::Network(format!("Не удалось создать сокет: {}", e)))?;

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

                // Добавить к локальным кандидатам
                {
                    let mut candidates = local_candidates.write().await;
                    candidates
                        .entry(component_id)
                        .or_insert_with(CandidateList::new)
                        .add(host_candidate.clone());
                }

                // Обновить статистику
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.candidates_gathered += 1;
                }

                // Отправить событие
                let _ = event_sender.send(IceEvent::CandidateAdded {
                    candidate: host_candidate,
                    component_id,
                });

                let _ = event_sender.send(IceEvent::GatheringCompleted {
                    component_id,
                    candidate_count: 1,
                });
            }
        }

        Ok(())
    }

    /// Вычислить приоритет кандидата
    fn calculate_priority(candidate_type: CandidateType, ip: &IpAddr) -> u32 {
        let type_preference = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };

        let local_preference = match ip {
            IpAddr::V4(_) => 65535,
            IpAddr::V6(_) => 65534,
        };

        (2_u32.pow(24) * type_preference) + (2_u32.pow(8) * local_preference) + 255
    }

    /// Обработать добавление удаленного кандидата
    async fn handle_add_remote_candidate(
        candidate: Candidate,
        component_id: u32,
        remote_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        _event_sender: &broadcast::Sender<IceEvent>,
    ) -> NatResult<()> {
        let mut candidates = remote_candidates.write().await;
        candidates
            .entry(component_id)
            .or_insert_with(CandidateList::new)
            .add(candidate);

        debug!("Добавлен удаленный кандидат для компонента {}", component_id);
        Ok(())
    }

    /// Обработать отправку данных
    async fn handle_send_data(
        component_id: u32,
        data: Vec<u8>,
        connections: &Arc<RwLock<HashMap<u32, ComponentConnection>>>,
    ) -> NatResult<usize> {
        let connections_guard = connections.read().await;

        if let Some(connection) = connections_guard.get(&component_id) {
            match connection.socket.send_to(&data, connection.selected_pair.remote_candidate.address.to_socket_addr()).await {
                Ok(sent) => {
                    debug!("Отправлено {} байт на компонент {}", sent, component_id);
                    Ok(sent)
                }
                Err(e) => Err(NatError::Network(format!("Не удалось отправить данные: {}", e))),
            }
        } else {
            Err(NatError::Connection(format!("Компонент {} не соединен", component_id)))
        }
    }

    /// Обработать перезапуск
    async fn handle_restart(
        state: &Arc<RwLock<IceState>>,
        role: &Arc<RwLock<Option<IceRole>>>,
        local_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        remote_candidates: &Arc<RwLock<HashMap<u32, CandidateList>>>,
        remote_credentials: &Arc<RwLock<Option<IceCredentials>>>,
        event_sender: &broadcast::Sender<IceEvent>,
    ) -> NatResult<()> {
        info!("Перезапуск ICE агента");

        // Очистить состояние
        *state.write().await = IceState::Gathering;
        *role.write().await = None;
        local_candidates.write().await.clear();
        remote_candidates.write().await.clear();
        *remote_credentials.write().await = None;

        // Отправить событие перезапуска
        let _ = event_sender.send(IceEvent::IceRestart);

        Ok(())
    }
}

impl CandidateAddress {
    /// Преобразовать в SocketAddr
    pub fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

/// Утилитарные функции для ICE
pub mod utils {
    use rand::Rng;

    /// Генерировать ICE ufrag
    pub fn generate_ufrag() -> String {
        use rand::Rng;
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

        let mut rng = rand::thread_rng();
        (0..4)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
            .collect()
    }

    /// Генерировать ICE пароль
    pub fn generate_password() -> String {
        use rand::Rng;
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

        let mut rng = rand::thread_rng();
        (0..22)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = IceConfig::default();
        let result = IceAgent::new(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ice_credentials_generation() {
        let ufrag = utils::generate_ufrag();
        let pwd = utils::generate_password();

        assert_eq!(ufrag.len(), 4);
        assert_eq!(pwd.len(), 22);
    }

    #[tokio::test]
    async fn test_priority_calculation() {
        let priority_host = IceAgent::calculate_priority(
            CandidateType::Host,
            &"192.168.1.1".parse().unwrap()
        );
        let priority_relay = IceAgent::calculate_priority(
            CandidateType::Relay,
            &"192.168.1.1".parse().unwrap()
        );

        assert!(priority_host > priority_relay);
    }
}
