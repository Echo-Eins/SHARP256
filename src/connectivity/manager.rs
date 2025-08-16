// src/connectivity/manager.rs
//! ConnectivityManager - центральный координатор всех методов подключения

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Notify};
use tokio::time::{timeout, sleep};
use tracing::{info, warn, debug, error, trace};
use parking_lot::Mutex;

use crate::connectivity::{
    Candidate, CandidatePair, CandidatePairState, ConnectionState,
    ConnectivityMetrics, ConnectivityCheckResult,
};
use crate::connectivity::config::{ConnectivityConfig, ConnectionMethod};
use crate::connectivity::transport::{Transport, EstablishedConnection, TransportType};
use crate::connectivity::signaling::SharpSignaling;

// Conditional imports based on features
#[cfg(feature = "webrtc-ice-stack")]
use crate::connectivity::ice::IceAgent;

#[cfg(feature = "libp2p-fallback")]
use crate::connectivity::fallback::LibP2pClient;

#[cfg(feature = "relay-encryption")]
use crate::connectivity::encryption::HeaderCrypto;

#[cfg(feature = "nat-router-pools")]
use crate::connectivity::router_pools::RouterPoolManager;

#[cfg(feature = "upnp-support")]
use crate::connectivity::upnp::UpnpManager;

/// События от ConnectivityManager
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
    /// Пара кандидатов номинирована
    CandidatePairNominated(CandidatePair),
    /// Соединение установлено
    ConnectionEstablished(EstablishedConnection),
    /// Соединение закрыто
    ConnectionClosed,
    /// Ошибка в процессе подключения
    Error(String),
    /// Метрики обновлены
    MetricsUpdated(ConnectivityMetrics),
}

/// Состояние попытки подключения
#[derive(Debug)]
struct ConnectionAttempt {
    method: ConnectionMethod,
    started_at: Instant,
    completed: bool,
    result: Option<Result<EstablishedConnection>>,
    error: Option<String>,
}

/// Главный координатор connectivity
pub struct ConnectivityManager {
    /// Конфигурация
    config: ConnectivityConfig,

    /// Текущее состояние
    state: Arc<RwLock<ConnectionState>>,

    /// Метрики
    metrics: Arc<RwLock<ConnectivityMetrics>>,

    /// ICE agent (primary method)
    #[cfg(feature = "webrtc-ice-stack")]
    ice_agent: Arc<RwLock<Option<IceAgent>>>,

    /// libp2p client (fallback)
    #[cfg(feature = "libp2p-fallback")]
    libp2p_client: Arc<RwLock<Option<LibP2pClient>>>,

    /// Router pool manager
    #[cfg(feature = "nat-router-pools")]
    router_pool_manager: Arc<RwLock<Option<RouterPoolManager>>>,

    /// UPnP manager
    #[cfg(feature = "upnp-support")]
    upnp_manager: Arc<RwLock<Option<UpnpManager>>>,

    /// Header encryption
    #[cfg(feature = "relay-encryption")]
    header_crypto: Arc<RwLock<Option<HeaderCrypto>>>,

    /// Signaling система
    signaling: Arc<RwLock<Option<SharpSignaling>>>,

    /// Локальные кандидаты
    local_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Удаленные кандидаты
    remote_candidates: Arc<RwLock<Vec<Candidate>>>,

    /// Активные пары кандидатов
    candidate_pairs: Arc<RwLock<Vec<CandidatePair>>>,

    /// Номинированная пара
    nominated_pair: Arc<RwLock<Option<CandidatePair>>>,

    /// Установленное соединение
    established_connection: Arc<RwLock<Option<EstablishedConnection>>>,

    /// Активные попытки подключения
    active_attempts: Arc<Mutex<HashMap<ConnectionMethod, ConnectionAttempt>>>,

    /// События для подписчиков
    event_tx: mpsc::UnboundedSender<ConnectivityEvent>,
    event_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ConnectivityEvent>>>>,

    /// Shutdown signal
    shutdown: Arc<AtomicBool>,

    /// Notification для ожидания завершения
    connection_complete: Arc<Notify>,
}

impl ConnectivityManager {
    /// Создание нового ConnectivityManager
    pub async fn new(config: ConnectivityConfig) -> Result<Self> {
        // Валидируем конфигурацию
        config.validate()?;

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let manager = Self {
            config: config.clone(),
            state: Arc::new(RwLock::new(ConnectionState::New)),
            metrics: Arc::new(RwLock::new(ConnectivityMetrics::new())),

            #[cfg(feature = "webrtc-ice-stack")]
            ice_agent: Arc::new(RwLock::new(None)),

            #[cfg(feature = "libp2p-fallback")]
            libp2p_client: Arc::new(RwLock::new(None)),

            #[cfg(feature = "nat-router-pools")]
            router_pool_manager: Arc::new(RwLock::new(None)),

            #[cfg(feature = "upnp-support")]
            upnp_manager: Arc::new(RwLock::new(None)),

            #[cfg(feature = "relay-encryption")]
            header_crypto: Arc::new(RwLock::new(None)),

            signaling: Arc::new(RwLock::new(None)),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            remote_candidates: Arc::new(RwLock::new(Vec::new())),
            candidate_pairs: Arc::new(RwLock::new(Vec::new())),
            nominated_pair: Arc::new(RwLock::new(None)),
            established_connection: Arc::new(RwLock::new(None)),
            active_attempts: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            event_rx: Arc::new(Mutex::new(Some(event_rx))),
            shutdown: Arc::new(AtomicBool::new(false)),
            connection_complete: Arc::new(Notify::new()),
        };

        // Инициализируем компоненты
        manager.initialize_components().await?;

        info!("ConnectivityManager initialized with config: {:?}",
              config.general.connection_methods_order);

        Ok(manager)
    }

    /// Инициализация всех компонентов
    async fn initialize_components(&self) -> Result<()> {
        // ICE Agent инициализация
        #[cfg(feature = "webrtc-ice-stack")]
        {
            let ice_agent = crate::connectivity::ice::IceAgent::new(
                self.config.ice.clone(),
                self.config.ice.controlling_role.unwrap_or(true)
            ).await?;
            *self.ice_agent.write().await = Some(ice_agent);
            debug!("ICE agent initialized");
        }

        // libp2p клиент
        #[cfg(feature = "libp2p-fallback")]
        if self.config.libp2p.enabled {
            let libp2p_client = crate::connectivity::fallback::LibP2pClient::new(
                self.config.libp2p.clone()
            ).await?;
            *self.libp2p_client.write().await = Some(libp2p_client);
            debug!("libp2p client initialized");
        }

        // Router pool manager
        #[cfg(feature = "nat-router-pools")]
        if self.config.router_pools.enabled {
            let router_manager = crate::connectivity::router_pools::RouterPoolManager::new(
                self.config.router_pools.clone()
            ).await?;
            *self.router_pool_manager.write().await = Some(router_manager);
            debug!("Router pool manager initialized");
        }

        // UPnP manager
        #[cfg(feature = "upnp-support")]
        if self.config.upnp.enabled {
            let upnp_manager = crate::connectivity::upnp::UpnpManager::new(
                self.config.upnp.clone()
            ).await?;
            *self.upnp_manager.write().await = Some(upnp_manager);
            debug!("UPnP manager initialized");
        }

        // Header encryption
        #[cfg(feature = "relay-encryption")]
        if self.config.relay.enable_header_encryption {
            // Генерируем ключ шифрования (в реальности должен обмениваться с peer)
            let key = rand::random::<[u8; 32]>();
            let header_crypto = crate::connectivity::encryption::HeaderCrypto::new(
                key,
                self.config.relay.header_encryption_algorithm
            );
            *self.header_crypto.write().await = Some(header_crypto);
            debug!("Header encryption initialized");
        }

        Ok(())
    }

    /// Главный метод установления соединения
    pub async fn establish_connection(
        &self,
        socket: Arc<UdpSocket>,
        peer_hint: Option<SocketAddr>,
        is_controlling: bool,
    ) -> Result<EstablishedConnection> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("ConnectivityManager is shutting down"));
        }

        info!("Starting connection establishment, peer_hint: {:?}, controlling: {}",
              peer_hint, is_controlling);

        // Обновляем состояние
        *self.state.write().await = ConnectionState::Gathering;
        self.emit_event(ConnectivityEvent::GatheringStarted).await;

        // Создаем signaling систему
        if let Some(peer_addr) = peer_hint {
            let signaling = SharpSignaling::new(socket.clone(), peer_addr);
            *self.signaling.write().await = Some(signaling);
        }

        // Сбор локальных кандидатов
        let local_candidates = self.gather_candidates(socket.clone()).await?;
        *self.local_candidates.write().await = local_candidates.clone();

        self.emit_event(ConnectivityEvent::GatheringComplete(local_candidates.clone())).await;

        // Обмен кандидатами с peer (если есть signaling)
        let remote_candidates = if let Some(signaling) = &*self.signaling.read().await {
            signaling.exchange_candidates(local_candidates).await?
        } else {
            // Если нет signaling, используем peer_hint как единственный кандидат
            peer_hint.map(|addr| vec![Candidate::host(addr)]).unwrap_or_default()
        };

        *self.remote_candidates.write().await = remote_candidates.clone();

        // Создаем пары кандидатов
        let candidate_pairs = self.create_candidate_pairs().await;
        *self.candidate_pairs.write().await = candidate_pairs;

        // Начинаем connectivity checks
        *self.state.write().await = ConnectionState::Connecting;
        self.emit_event(ConnectivityEvent::ConnectivityChecksStarted).await;

        // Запускаем параллельные попытки подключения
        let connection = self.run_parallel_connection_attempts(socket).await?;

        // Обновляем состояние
        *self.state.write().await = ConnectionState::Connected;
        *self.established_connection.write().await = Some(connection.clone());

        // Обновляем метрики
        {
            let mut metrics = self.metrics.write().await;
            metrics.mark_connected();
            metrics.connection_method = Some(format!("{:?}", connection.transport_type()));
        }

        self.emit_event(ConnectivityEvent::ConnectionEstablished(connection.clone())).await;
        self.connection_complete.notify_waiters();

        info!("Connection established successfully via {:?}", connection.transport_type());

        Ok(connection)
    }

    /// Сбор локальных кандидатов из всех источников
    async fn gather_candidates(&self, socket: Arc<UdpSocket>) -> Result<Vec<Candidate>> {
        let mut candidates = Vec::new();
        let local_addr = socket.local_addr()?;

        info!("Gathering candidates from local address: {}", local_addr);

        // Host кандидат (всегда есть)
        candidates.push(Candidate::host(local_addr));
        self.emit_event(ConnectivityEvent::CandidateGathered(candidates[0].clone())).await;

        // Параллельно собираем кандидаты из разных источников
        let mut tasks = Vec::new();

        // ICE кандидаты (STUN/TURN)
        #[cfg(feature = "webrtc-ice-stack")]
        if let Some(ice_agent) = &*self.ice_agent.read().await {
            let ice_agent = ice_agent.clone();
            let event_tx = self.event_tx.clone();
            tasks.push(tokio::spawn(async move {
                match ice_agent.gather_candidates_with_progress(event_tx).await {
                    Ok(ice_candidates) => {
                        debug!("ICE gathered {} candidates", ice_candidates.len());
                        ice_candidates
                    }
                    Err(e) => {
                        warn!("ICE candidate gathering failed: {}", e);
                        Vec::new()
                    }
                }
            }));
        }

        // UPnP кандидаты
        #[cfg(feature = "upnp-support")]
        if let Some(upnp_manager) = &*self.upnp_manager.read().await {
            let upnp_manager = upnp_manager.clone();
            let local_port = local_addr.port();
            tasks.push(tokio::spawn(async move {
                match upnp_manager.create_port_mapping(local_port).await {
                    Ok(mapped_port) => {
                        if let Ok(external_ip) = upnp_manager.get_external_ip().await {
                            let external_addr = SocketAddr::new(external_ip, mapped_port);
                            debug!("UPnP candidate: {}", external_addr);
                            vec![Candidate::server_reflexive(external_addr, local_addr)]
                        } else {
                            Vec::new()
                        }
                    }
                    Err(e) => {
                        debug!("UPnP mapping failed: {}", e);
                        Vec::new()
                    }
                }
            }));
        }

        // Router pool кандидаты
        #[cfg(feature = "nat-router-pools")]
        if let Some(router_manager) = &*self.router_pool_manager.read().await {
            let router_manager = router_manager.clone();
            tasks.push(tokio::spawn(async move {
                match router_manager.discover_routers().await {
                    Ok(router_candidates) => {
                        debug!("Router pools found {} candidates", router_candidates.len());
                        router_candidates
                    }
                    Err(e) => {
                        debug!("Router pool discovery failed: {}", e);
                        Vec::new()
                    }
                }
            }));
        }

        // Relay кандидаты
        for relay_server in &self.config.relay.sharp_relay_servers {
            let relay_addr = relay_server.address;
            let encryption_capable = relay_server.supports_header_encryption;
            candidates.push(Candidate::relay(relay_addr, local_addr, encryption_capable));
            self.emit_event(ConnectivityEvent::CandidateGathered(candidates.last().unwrap().clone())).await;
        }

        // Ждем результаты от всех задач
        let gathering_timeout = self.config.ice.gathering_timeout;
        for task in tasks {
            match timeout(gathering_timeout, task).await {
                Ok(Ok(new_candidates)) => {
                    for candidate in new_candidates {
                        candidates.push(candidate.clone());
                        self.emit_event(ConnectivityEvent::CandidateGathered(candidate)).await;
                    }
                }
                Ok(Err(e)) => {
                    warn!("Candidate gathering task failed: {}", e);
                }
                Err(_) => {
                    warn!("Candidate gathering task timed out");
                }
            }
        }

        // Сортируем кандидаты по приоритету
        candidates.sort_by_key(|c| std::cmp::Reverse(c.priority));

        info!("Gathered {} candidates total", candidates.len());
        Ok(candidates)
    }

    /// Создание пар кандидатов для проверки
    async fn create_candidate_pairs(&self) -> Vec<CandidatePair> {
        let local_candidates = self.local_candidates.read().await;
        let remote_candidates = self.remote_candidates.read().await;

        let mut pairs = Vec::new();

        for local in local_candidates.iter() {
            for remote in remote_candidates.iter() {
                if local.is_compatible_with(remote) {
                    pairs.push(CandidatePair::new(local.clone(), remote.clone()));
                }
            }
        }

        // Сортируем пары по приоритету
        pairs.sort_by_key(|p| std::cmp::Reverse(p.priority));

        // Ограничиваем количество пар
        pairs.truncate(self.config.ice.max_candidate_pairs);

        debug!("Created {} candidate pairs", pairs.len());
        pairs
    }

    /// Запуск параллельных попыток подключения
    async fn run_parallel_connection_attempts(
        &self,
        socket: Arc<UdpSocket>,
    ) -> Result<EstablishedConnection> {
        let methods = &self.config.general.connection_methods_order;
        let max_concurrent = self.config.general.max_concurrent_attempts;
        let connection_timeout = self.config.general.connection_timeout;

        info!("Starting parallel connection attempts: {:?}", methods);

        // Семафор для ограничения количества параллельных попыток
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
        let mut tasks = Vec::new();

        for &method in methods {
            let semaphore = semaphore.clone();
            let socket = socket.clone();
            let self_clone = self.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                self_clone.attempt_connection_method(method, socket).await
            }));
        }

        // Ждем первого успешного результата
        let start_time = Instant::now();

        loop {
            if start_time.elapsed() > connection_timeout {
                error!("Connection timeout exceeded");
                return Err(anyhow::anyhow!("Connection timeout"));
            }

            if self.shutdown.load(Ordering::Relaxed) {
                return Err(anyhow::anyhow!("Shutdown requested"));
            }

            // Проверяем завершенные задачи
            for (i, task) in tasks.iter_mut().enumerate() {
                if task.is_finished() {
                    match task.await {
                        Ok(Ok(connection)) => {
                            info!("Connection established via method index {}", i);

                            // Отменяем остальные задачи
                            for (j, other_task) in tasks.iter().enumerate() {
                                if j != i && !other_task.is_finished() {
                                    other_task.abort();
                                }
                            }

                            return Ok(connection);
                        }
                        Ok(Err(e)) => {
                            debug!("Connection method {} failed: {}", i, e);
                        }
                        Err(e) => {
                            debug!("Connection task {} panicked: {}", i, e);
                        }
                    }
                }
            }

            // Небольшая пауза перед следующей проверкой
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Попытка подключения через определенный метод
    async fn attempt_connection_method(
        &self,
        method: ConnectionMethod,
        socket: Arc<UdpSocket>,
    ) -> Result<EstablishedConnection> {
        let start_time = Instant::now();
        debug!("Attempting connection via {:?}", method);

        // Записываем попытку
        {
            let mut attempts = self.active_attempts.lock();
            attempts.insert(method, ConnectionAttempt {
                method,
                started_at: start_time,
                completed: false,
                result: None,
                error: None,
            });
        }

        let result = match method {
            ConnectionMethod::Direct => {
                self.attempt_direct_connection(socket).await
            }

            ConnectionMethod::Ice => {
                #[cfg(feature = "webrtc-ice-stack")]
                {
                    self.attempt_ice_connection(socket).await
                }
                #[cfg(not(feature = "webrtc-ice-stack"))]
                {
                    Err(anyhow::anyhow!("ICE not available"))
                }
            }

            ConnectionMethod::Upnp => {
                #[cfg(feature = "upnp-support")]
                {
                    self.attempt_upnp_connection(socket).await
                }
                #[cfg(not(feature = "upnp-support"))]
                {
                    Err(anyhow::anyhow!("UPnP not available"))
                }
            }

            ConnectionMethod::RouterPools => {
                #[cfg(feature = "nat-router-pools")]
                {
                    self.attempt_router_pools_connection(socket).await
                }
                #[cfg(not(feature = "nat-router-pools"))]
                {
                    Err(anyhow::anyhow!("Router pools not available"))
                }
            }

            ConnectionMethod::LibP2p => {
                #[cfg(feature = "libp2p-fallback")]
                {
                    self.attempt_libp2p_connection(socket).await
                }
                #[cfg(not(feature = "libp2p-fallback"))]
                {
                    Err(anyhow::anyhow!("libp2p not available"))
                }
            }

            ConnectionMethod::Relay => {
                self.attempt_relay_connection(socket).await
            }
        };

        // Обновляем попытку
        {
            let mut attempts = self.active_attempts.lock();
            if let Some(attempt) = attempts.get_mut(&method) {
                attempt.completed = true;
                attempt.result = Some(result.clone());
                if let Err(ref e) = result {
                    attempt.error = Some(e.to_string());
                }
            }
        }

        let elapsed = start_time.elapsed();
        match &result {
            Ok(_) => {
                info!("Connection via {:?} succeeded in {:?}", method, elapsed);
            }
            Err(e) => {
                debug!("Connection via {:?} failed in {:?}: {}", method, elapsed, e);
            }
        }

        result
    }

    /// Попытка прямого соединения
    async fn attempt_direct_connection(&self, socket: Arc<UdpSocket>) -> Result<EstablishedConnection> {
        let remote_candidates = self.remote_candidates.read().await;

        for candidate in remote_candidates.iter() {
            if candidate.candidate_type == crate::connectivity::CandidateType::Host {
                // Проверяем прямое соединение
                let test_result = self.test_connectivity(&socket, candidate.address).await;

                if test_result.is_ok() {
                    let local_addr = socket.local_addr()?;
                    return Ok(EstablishedConnection::new(
                        Box::new(crate::connectivity::transport::DirectTransport::new(
                            socket, local_addr, candidate.address
                        )),
                        TransportType::Direct,
                        local_addr,
                        candidate.address,
                    ));
                }
            }
        }

        Err(anyhow::anyhow!("Direct connection failed"))
    }

    /// Попытка ICE соединения
    #[cfg(feature = "webrtc-ice-stack")]
    async fn attempt_ice_connection(&self, socket: Arc<UdpSocket>) -> Result<EstablishedConnection> {
        if let Some(ice_agent) = &*self.ice_agent.read().await {
            // Добавляем remote кандидаты в ICE agent
            let remote_candidates = self.remote_candidates.read().await;
            for candidate in remote_candidates.iter() {
                ice_agent.add_remote_candidate(candidate.clone()).await?;
            }

            // Запускаем connectivity checks
            let check_results = ice_agent.perform_connectivity_checks().await?;

            // Находим успешную пару
            for result in check_results {
                if result.success {
                    self.emit_event(ConnectivityEvent::ConnectivityCheckResult(result.clone())).await;

                    if let Some(nominated_pair) = ice_agent.nominate_pair(result.pair.clone()).await? {
                        *self.nominated_pair.write().await = Some(nominated_pair.clone());
                        self.emit_event(ConnectivityEvent::CandidatePairNominated(nominated_pair.clone())).await;

                        return Ok(EstablishedConnection::new(
                            Box::new(crate::connectivity::transport::IceTransport::new(
                                ice_agent.get_connection().await?, nominated_pair
                            )),
                            TransportType::IceNominated,
                            nominated_pair.local.address,
                            nominated_pair.remote.address,
                        ));
                    }
                }
            }
        }

        Err(anyhow::anyhow!("ICE connection failed"))
    }

    /// Попытка UPnP соединения
    #[cfg(feature = "upnp-support")]
    async fn attempt_upnp_connection(&self, socket: Arc<UdpSocket>) -> Result<EstablishedConnection> {
        if let Some(upnp_manager) = &*self.upnp_manager.read().await {
            let local_addr = socket.local_addr()?;
            let mapped_port = upnp_manager.create_port_mapping(local_addr.port()).await?;
            let external_ip = upnp_manager.get_external_ip().await?;
            let external_addr = SocketAddr::new(external_ip, mapped_port);

            // Проверяем, работает ли внешний адрес
            if let Some(peer_addr) = self.remote_candidates.read().await.first() {
                let test_result = self.test_connectivity(&socket, peer_addr.address).await;

                if test_result.is_ok() {
                    return Ok(EstablishedConnection::new(
                        Box::new(crate::connectivity::transport::UpnpTransport::new(
                            socket, external_addr, peer_addr.address, upnp_manager.clone()
                        )),
                        TransportType::Direct, // UPnP essentially makes it direct
                        external_addr,
                        peer_addr.address,
                    ));
                }
            }
        }

        Err(anyhow::anyhow!("UPnP connection failed"))
    }

    /// Попытка соединения через router pools
    #[cfg(feature = "nat-router-pools")]
    async fn attempt_router_pools_connection(&self, socket: Arc<UdpSocket>) -> Result<EstablishedConnection> {
        if let Some(router_manager) = &*self.router_pool_manager.read().await {
            let router_candidates = router_manager.discover_routers().await?;

            for router_candidate in router_candidates {
                let test_result = self.test_connectivity(&socket, router_candidate.address).await;

                if test_result.is_ok() {
                    let local_addr = socket.local_addr()?;
                    return Ok(EstablishedConnection::new(
                        Box::new(crate::connectivity::transport::RouterPoolTransport::new(
                            socket, local_addr, router_candidate.address
                        )),
                        TransportType::Direct, // Router pool acts as intermediary
                        local_addr,
                        router_candidate.address,
                    ));
                }
            }
        }

        Err(anyhow::anyhow!("Router pools connection failed"))
    }

    /// Попытка libp2p соединения
    #[cfg(feature = "libp2p-fallback")]
    async fn attempt_libp2p_connection(&self, _socket: Arc<UdpSocket>) -> Result<EstablishedConnection> {
        if let Some(libp2p_client) = &*self.libp2p_client.read().await {
            // libp2p использует свой собственный transport layer
            let connection = libp2p_client.establish_connection().await?;

            return Ok(EstablishedConnection::new(
                Box::new(connection),
                TransportType::Relayed { encryption: false },
                SocketAddr::new("127.0.0.1".parse().unwrap(), 0), // Placeholder
                SocketAddr::new("127.0.0.1".parse().unwrap(), 0), // Placeholder
            ));
        }

        Err(anyhow::anyhow!("libp2p connection failed"))
    }

    /// Попытка relay соединения
    async fn attempt_relay_connection(&self, socket: Arc<UdpSocket>) -> Result<EstablishedConnection> {
        for relay_server in &self.config.relay.sharp_relay_servers {
            let test_result = self.test_connectivity(&socket, relay_server.address).await;

            if test_result.is_ok() {
                let local_addr = socket.local_addr()?;
                let encryption_enabled = relay_server.supports_header_encryption &&
                    self.config.relay.enable_header_encryption;

                return Ok(EstablishedConnection::new(
                    Box::new(crate::connectivity::transport::RelayTransport::new(
                        socket,
                        local_addr,
                        relay_server.address,
                        encryption_enabled,
                        #[cfg(feature = "relay-encryption")]
                        self.header_crypto.read().await.clone(),
                        #[cfg(not(feature = "relay-encryption"))]
                        None,
                    )),
                    TransportType::Relayed { encryption: encryption_enabled },
                    local_addr,
                    relay_server.address,
                ));
            }
        }

        Err(anyhow::anyhow!("Relay connection failed"))
    }

    /// Тестирование connectivity с адресом
    async fn test_connectivity(&self, socket: &UdpSocket, target: SocketAddr) -> Result<Duration> {
        let start = Instant::now();
        let test_data = b"SHARP_CONNECTIVITY_TEST";

        socket.send_to(test_data, target).await?;

        // Ждем ответ с таймаутом
        let mut buffer = vec![0u8; 1024];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) => {
                if addr == target && size >= test_data.len() {
                    Ok(start.elapsed())
                } else {
                    Err(anyhow::anyhow!("Invalid response"))
                }
            }
            _ => Err(anyhow::anyhow!("No response"))
        }
    }

    /// Добавление удаленных кандидатов
    pub async fn add_remote_candidates(&self, candidates: Vec<Candidate>) -> Result<()> {
        let mut remote_candidates = self.remote_candidates.write().await;
        for candidate in candidates {
            remote_candidates.push(candidate.clone());
            self.emit_event(ConnectivityEvent::CandidateGathered(candidate)).await;
        }

        // Пересоздаем пары кандидатов
        let new_pairs = self.create_candidate_pairs().await;
        *self.candidate_pairs.write().await = new_pairs;

        Ok(())
    }

    /// Получение собранных кандидатов
    pub async fn gather_candidates(&self) -> Result<Vec<Candidate>> {
        Ok(self.local_candidates.read().await.clone())
    }

    /// Получение публичного адреса
    pub async fn get_connectable_address(&self) -> Result<SocketAddr> {
        let local_candidates = self.local_candidates.read().await;

        // Ищем лучший кандидат для публикации
        for candidate in local_candidates.iter() {
            match candidate.candidate_type {
                crate::connectivity::CandidateType::ServerReflexive => {
                    return Ok(candidate.address);
                }
                crate::connectivity::CandidateType::Relay => {
                    if candidate.attributes.encryption_capable {
                        return Ok(candidate.address);
                    }
                }
                _ => {}
            }
        }

        // Fallback на первый доступный
        local_candidates.first()
            .map(|c| c.address)
            .ok_or_else(|| anyhow::anyhow!("No connectable address available"))
    }

    /// Получение состояния подключения
    pub fn get_connection_state(&self) -> ConnectionState {
        // Используем try_read для неблокирующего доступа
        self.state.try_read().map(|s| *s).unwrap_or(ConnectionState::New)
    }

    /// Подписка на события
    pub fn subscribe_events(&self) -> mpsc::UnboundedReceiver<ConnectivityEvent> {
        let mut receiver_opt = self.event_rx.lock();
        receiver_opt.take().unwrap_or_else(|| {
            let (_, rx) = mpsc::unbounded_channel();
            rx
        })
    }

    /// Отправка события подписчикам
    async fn emit_event(&self, event: ConnectivityEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down ConnectivityManager");

        self.shutdown.store(true, Ordering::Relaxed);

        // Закрываем все активные соединения
        if let Some(connection) = &*self.established_connection.read().await {
            // Закрытие connection implementation specific
        }

        // Cleanup компонентов
        #[cfg(feature = "upnp-support")]
        if let Some(upnp_manager) = &*self.upnp_manager.read().await {
            let _ = upnp_manager.cleanup().await;
        }

        *self.state.write().await = ConnectionState::Closed;
        self.emit_event(ConnectivityEvent::ConnectionClosed).await;

        Ok(())
    }
}

// Implement Clone для использования в async tasks
impl Clone for ConnectivityManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: self.state.clone(),
            metrics: self.metrics.clone(),

            #[cfg(feature = "webrtc-ice-stack")]
            ice_agent: self.ice_agent.clone(),

            #[cfg(feature = "libp2p-fallback")]
            libp2p_client: self.libp2p_client.clone(),

            #[cfg(feature = "nat-router-pools")]
            router_pool_manager: self.router_pool_manager.clone(),

            #[cfg(feature = "upnp-support")]
            upnp_manager: self.upnp_manager.clone(),

            #[cfg(feature = "relay-encryption")]
            header_crypto: self.header_crypto.clone(),

            signaling: self.signaling.clone(),
            local_candidates: self.local_candidates.clone(),
            remote_candidates: self.remote_candidates.clone(),
            candidate_pairs: self.candidate_pairs.clone(),
            nominated_pair: self.nominated_pair.clone(),
            established_connection: self.established_connection.clone(),
            active_attempts: self.active_attempts.clone(),
            event_tx: self.event_tx.clone(),
            event_rx: self.event_rx.clone(),
            shutdown: self.shutdown.clone(),
            connection_complete: self.connection_complete.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectivity::config::ConnectivityConfig;

    #[tokio::test]
    async fn test_connectivity_manager_creation() {
        let config = ConnectivityConfig::for_testing();
        let manager = ConnectivityManager::new(config).await.unwrap();

        assert_eq!(manager.get_connection_state(), ConnectionState::New);
    }

    #[tokio::test]
    async fn test_candidate_gathering() {
        let config = ConnectivityConfig::for_testing();
        let manager = ConnectivityManager::new(config).await.unwrap();

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let candidates = manager.gather_candidates(socket).await.unwrap();

        assert!(!candidates.is_empty());
        assert!(candidates.iter().any(|c| c.candidate_type == crate::connectivity::CandidateType::Host));
    }
}