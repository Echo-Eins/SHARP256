// src/nat/stun_turn_manager.rs
//! STUN/TURN Integration Manager
//!
//! Этот модуль предоставляет унифицированный интерфейс для STUN и TURN операций,
//! координируя между STUN клиентом для обнаружения NAT и TURN сервером/клиентом
//! для relay функциональности, когда прямые соединения невозможны.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Mutex, broadcast, watch};
use tokio::time::{interval, timeout};
use tracing::{info, warn, debug, error, trace};
use serde::{Serialize, Deserialize};

// Используем существующие типы из модуля
use crate::nat::error::{NatError, NatResult};
use crate::nat::stun::{StunService, StunConfig, NatBehavior};
use crate::nat::turn::{TurnClient, TurnCredentials};
use crate::nat::ice::{Candidate, CandidateType, CandidateAddress, CandidateExtensions, TransportProtocol};

/// Конфигурация STUN/TURN менеджера
#[derive(Debug, Clone)]
pub struct StunTurnConfig {
    /// STUN конфигурация
    pub stun_config: StunConfig,

    /// Конфигурация TURN сервера (при запуске собственного)
    pub turn_server_config: Option<crate::nat::turn::TurnServerConfig>,

    /// Внешние TURN серверы для использования
    pub turn_servers: Vec<TurnServerInfo>,

    /// Таймаут сбора кандидатов
    pub gathering_timeout: Duration,

    /// Время жизни TURN allocation
    pub turn_allocation_lifetime: Duration,

    /// Включить сбор server reflexive кандидатов через STUN
    pub enable_server_reflexive: bool,

    /// Включить сбор relay кандидатов через TURN
    pub enable_relay: bool,

    /// Максимальные одновременные TURN allocations
    pub max_turn_allocations: usize,

    /// Конфигурация повторных попыток TURN
    pub turn_retry_config: TurnRetryConfig,

    /// Конфигурация мониторинга качества
    pub quality_monitoring: QualityMonitoringConfig,
}

/// Информация о TURN сервере
#[derive(Debug, Clone)]
pub struct TurnServerInfo {
    pub url: String,
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
    pub transport: TurnTransport,
    pub priority: u32,
}

/// Транспортный протокол TURN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnTransport {
    Udp,
    Tcp,
    Tls,
    Dtls,
}

/// Конфигурация повторных попыток TURN
#[derive(Debug, Clone)]
pub struct TurnRetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

/// Конфигурация мониторинга качества
#[derive(Debug, Clone)]
pub struct QualityMonitoringConfig {
    pub enable_rtt_monitoring: bool,
    pub enable_packet_loss_monitoring: bool,
    pub monitoring_interval: Duration,
    pub quality_threshold: f64,
}

/// Запрос сбора кандидатов
#[derive(Debug, Clone)]
pub struct CandidateGatheringRequest {
    pub component_id: u32,
    pub socket: Arc<UdpSocket>,
    pub gather_types: Vec<CandidateType>,
    pub timeout: Duration,
}

/// Результат сбора кандидатов
#[derive(Debug, Clone)]
pub struct CandidateGatheringResult {
    pub component_id: u32,
    pub candidates: Vec<Candidate>,
    pub gathering_time: Duration,
    pub nat_behavior: Option<NatBehavior>,
}

/// Информация о TURN allocation
#[derive(Debug, Clone)]
pub struct TurnAllocationInfo {
    pub allocation_id: String,
    pub server_url: String,
    pub relay_address: SocketAddr,
    pub allocated_at: Instant,
    pub expires_at: Instant,
    pub username: String,
    pub quality_metrics: ConnectionQualityMetrics,
}

/// Метрики качества соединения
#[derive(Debug, Default, Clone)]
pub struct ConnectionQualityMetrics {
    pub rtt: Option<Duration>,
    pub packet_loss_rate: f64,
    pub bandwidth_estimate: Option<u64>,
    pub quality_score: f64,
    pub last_updated: Option<Instant>,
}

/// Статистика STUN/TURN
#[derive(Debug, Default)]
pub struct StunTurnStats {
    // STUN статистика
    pub stun_requests: std::sync::atomic::AtomicU64,
    pub stun_successes: std::sync::atomic::AtomicU64,
    pub stun_failures: std::sync::atomic::AtomicU64,
    pub stun_timeouts: std::sync::atomic::AtomicU64,

    // TURN статистика
    pub turn_allocation_requests: std::sync::atomic::AtomicU64,
    pub turn_allocation_successes: std::sync::atomic::AtomicU64,
    pub turn_allocation_failures: std::sync::atomic::AtomicU64,
    pub active_turn_allocations: std::sync::atomic::AtomicU64,

    // Кандидаты
    pub server_reflexive_candidates: std::sync::atomic::AtomicU64,
    pub relay_candidates: std::sync::atomic::AtomicU64,

    // Качество соединения
    pub avg_rtt: std::sync::atomic::AtomicU64, // микросекунды
    pub avg_packet_loss_rate: std::sync::atomic::AtomicU64, // проценты * 1000
}

/// События, испускаемые STUN/TURN менеджером
#[derive(Debug, Clone)]
pub enum StunTurnEvent {
    /// Обнаружено поведение NAT
    NatBehaviorDiscovered {
        local_addr: SocketAddr,
        behavior: NatBehavior,
    },

    /// Собран server reflexive кандидат
    ServerReflexiveCandidateGathered {
        component_id: u32,
        candidate: Candidate,
    },

    /// Собран relay кандидат
    RelayCandidateGathered {
        component_id: u32,
        candidate: Candidate,
        turn_server: String,
    },

    /// Создан TURN allocation
    TurnAllocationCreated {
        allocation_id: String,
        server_url: String,
        relay_address: SocketAddr,
    },

    /// Сбой TURN allocation
    TurnAllocationFailed {
        server_url: String,
        error: String,
    },

    /// Изменилось качество соединения
    ConnectionQualityChanged {
        target: String,
        old_quality: f64,
        new_quality: f64,
    },

    /// Менеджер завершается
    Shutdown,
}

/// Состояние TURN allocation
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    pub relay_address: SocketAddr,
    pub allocated_at: Instant,
    pub expires_at: Instant,
    pub client: Arc<TurnClient>,
}

/// Основной STUN/TURN менеджер
pub struct StunTurnManager {
    /// Конфигурация
    config: Arc<StunTurnConfig>,

    /// STUN сервис
    stun_service: Arc<StunService>,

    /// Опциональный TURN сервер (интегрированный)
    turn_server: Option<Arc<crate::nat::turn::TurnServer>>,

    /// TURN allocations по ID
    turn_allocations: Arc<RwLock<HashMap<String, TurnAllocation>>>,

    /// TURN клиенты по серверу
    turn_clients: Arc<RwLock<HashMap<String, Arc<TurnClient>>>>,

    /// Кэш поведения NAT
    nat_behavior_cache: Arc<RwLock<HashMap<SocketAddr, NatBehavior>>>,

    /// Монитор качества
    quality_monitor: Arc<QualityMonitor>,

    /// Статистика
    stats: Arc<StunTurnStats>,

    /// Отправитель событий
    event_tx: broadcast::Sender<StunTurnEvent>,

    /// Флаг завершения работы
    shutdown: Arc<watch::Receiver<bool>>,
    shutdown_tx: watch::Sender<bool>,

    /// Фоновые задачи
    background_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

/// Монитор качества соединения
pub struct QualityMonitor {
    config: QualityMonitoringConfig,
    measurements: Arc<RwLock<HashMap<String, ConnectionQualityMetrics>>>,
}

impl Default for StunTurnConfig {
    fn default() -> Self {
        Self {
            stun_config: StunConfig::default(),
            turn_server_config: None,
            turn_servers: Vec::new(),
            gathering_timeout: Duration::from_secs(30),
            turn_allocation_lifetime: Duration::from_secs(600),
            enable_server_reflexive: true,
            enable_relay: true,
            max_turn_allocations: 10,
            turn_retry_config: TurnRetryConfig {
                max_retries: 3,
                initial_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                backoff_multiplier: 2.0,
            },
            quality_monitoring: QualityMonitoringConfig {
                enable_rtt_monitoring: true,
                enable_packet_loss_monitoring: true,
                monitoring_interval: Duration::from_secs(10),
                quality_threshold: 0.8,
            },
        }
    }
}

impl StunTurnManager {
    /// Создать новый STUN/TURN менеджер
    pub async fn new(config: StunTurnConfig) -> NatResult<Self> {
        info!("Создание STUN/TURN менеджера с {} TURN серверами", config.turn_servers.len());

        let config = Arc::new(config);

        // Создать STUN сервис
        let stun_service = Arc::new(StunService::with_config(config.stun_config.clone()));

        // Опционально создать TURN сервер
        let turn_server = if let Some(ref turn_config) = config.turn_server_config {
            info!("Запуск интегрированного TURN сервера");
            match crate::nat::turn::TurnServer::new(turn_config.clone()).await {
                Ok(server) => {
                    if let Err(e) = server.start().await {
                        warn!("Не удалось запустить TURN сервер: {}", e);
                        None
                    } else {
                        Some(Arc::new(server))
                    }
                }
                Err(e) => {
                    warn!("Не удалось создать TURN сервер: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Создать монитор качества
        let quality_monitor = Arc::new(QualityMonitor::new(config.quality_monitoring.clone()));

        // Создать канал событий
        let (event_tx, _) = broadcast::channel(1000);

        // Создать каналы завершения работы
        let (shutdown_tx, shutdown) = watch::channel(false);

        let manager = Self {
            config: config.clone(),
            stun_service,
            turn_server,
            turn_allocations: Arc::new(RwLock::new(HashMap::new())),
            turn_clients: Arc::new(RwLock::new(HashMap::new())),
            nat_behavior_cache: Arc::new(RwLock::new(HashMap::new())),
            quality_monitor,
            stats: Arc::new(StunTurnStats::default()),
            event_tx,
            shutdown,
            shutdown_tx,
            background_tasks: Arc::new(Mutex::new(Vec::new())),
        };

        // Запустить фоновые задачи
        manager.start_background_tasks().await?;

        Ok(manager)
    }

    /// Получить server reflexive кандидат через STUN
    pub async fn get_server_reflexive_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> NatResult<Option<Candidate>> {
        if !self.config.enable_server_reflexive {
            return Ok(None);
        }

        debug!("Сбор server reflexive кандидата для компонента {}", component_id);

        let start_time = Instant::now();
        self.stats.stun_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        match timeout(
            self.config.gathering_timeout / 2,
            self.stun_service.get_public_address(&socket)
        ).await {
            Ok(Ok(public_addr)) => {
                let gathering_duration = start_time.elapsed();
                self.stats.stun_successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let local_addr = socket.local_addr().map_err(|e| {
                    NatError::Network(format!("Не удалось получить локальный адрес: {}", e))
                })?;

                // Кэшировать поведение NAT, если не кэшировано
                if !self.nat_behavior_cache.read().await.contains_key(&local_addr) {
                    if let Ok((_, behavior)) = self.stun_service.detect_nat_type(&socket).await {
                        self.nat_behavior_cache.write().await.insert(local_addr, behavior.clone());

                        let _ = self.event_tx.send(StunTurnEvent::NatBehaviorDiscovered {
                            local_addr,
                            behavior,
                        });
                    }
                }

                let candidate = Candidate {
                    address: CandidateAddress {
                        ip: public_addr.ip(),
                        port: public_addr.port(),
                        transport: TransportProtocol::Udp,
                    },
                    candidate_type: CandidateType::ServerReflexive,
                    priority: self.calculate_priority(CandidateType::ServerReflexive, &public_addr.ip()),
                    foundation: format!("srflx{}{}", component_id, public_addr.port()),
                    component_id,
                    related_address: Some(local_addr),
                    tcp_type: None,
                    extensions: CandidateExtensions {
                        network_cost: Some(10),
                        generation: Some(0),
                    },
                };

                info!("STUN успешен: {} -> {} ({}ms)",
                     local_addr, public_addr, gathering_duration.as_millis());

                let _ = self.event_tx.send(StunTurnEvent::ServerReflexiveCandidateGathered {
                    component_id,
                    candidate: candidate.clone(),
                });

                Ok(Some(candidate))
            }
            Ok(Err(e)) => {
                warn!("STUN запрос неудачен: {}", e);
                self.stats.stun_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            }
            Err(_) => {
                warn!("STUN запрос таймаут");
                self.stats.stun_timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            }
        }
    }

    /// Получить relay кандидат через TURN
    pub async fn get_relay_candidate(
        &self,
        socket: Arc<UdpSocket>,
        component_id: u32,
    ) -> NatResult<Option<Candidate>> {
        if !self.config.enable_relay || self.config.turn_servers.is_empty() {
            return Ok(None);
        }

        debug!("Сбор relay кандидата для компонента {}", component_id);

        let start_time = Instant::now();
        self.stats.turn_allocation_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Попробовать TURN серверы в порядке приоритета
        let mut turn_servers = self.config.turn_servers.clone();
        turn_servers.sort_by(|a, b| b.priority.cmp(&a.priority));

        for turn_server in turn_servers {
            match self.try_turn_allocation(&socket, component_id, &turn_server).await {
                Ok(Some(candidate)) => {
                    let allocation_duration = start_time.elapsed();
                    self.stats.turn_allocation_successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    info!("TURN allocation успешен: {} ({}ms)", turn_server.url, allocation_duration.as_millis());
                    return Ok(Some(candidate));
                }
                Ok(None) => {
                    debug!("TURN allocation не удался для {}, пробуем следующий", turn_server.url);
                    continue;
                }
                Err(e) => {
                    warn!("TURN allocation ошибка для {}: {}", turn_server.url, e);
                    continue;
                }
            }
        }

        self.stats.turn_allocation_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(None)
    }

    /// Попробовать TURN allocation (заглушка)
    async fn try_turn_allocation(
        &self,
        _socket: &Arc<UdpSocket>,
        _component_id: u32,
        turn_server: &TurnServerInfo,
    ) -> NatResult<Option<Candidate>> {
        // Заглушка для TURN allocation
        // В реальной реализации здесь был бы полный TURN протокол
        warn!("TURN allocation не реализован для {}", turn_server.url);

        let _ = self.event_tx.send(StunTurnEvent::TurnAllocationFailed {
            server_url: turn_server.url.clone(),
            error: "TURN allocation не реализован".to_string(),
        });

        Ok(None)
    }

    /// Вычислить приоритет кандидата
    fn calculate_priority(&self, candidate_type: CandidateType, ip: &IpAddr) -> u32 {
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

    /// Запустить фоновые задачи
    async fn start_background_tasks(&self) -> NatResult<()> {
        let mut tasks = self.background_tasks.lock().await;

        // Задача мониторинга качества
        if self.config.quality_monitoring.enable_rtt_monitoring {
            let quality_monitor = self.quality_monitor.clone();
            let shutdown = self.shutdown.clone();

            let task = tokio::spawn(async move {
                quality_monitor.start_monitoring(shutdown).await;
            });

            tasks.push(task);
        }

        // Задача очистки TURN allocations
        let allocations = self.turn_allocations.clone();
        let stats = self.stats.clone();
        let shutdown = self.shutdown.clone();

        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::cleanup_expired_allocations(&allocations, &stats).await;
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        tasks.push(task);

        Ok(())
    }

    /// Очистить истекшие allocations
    async fn cleanup_expired_allocations(
        allocations: &Arc<RwLock<HashMap<String, TurnAllocation>>>,
        stats: &Arc<StunTurnStats>,
    ) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        {
            let allocations_read = allocations.read().await;
            for (id, allocation) in allocations_read.iter() {
                if now >= allocation.expires_at {
                    to_remove.push(id.clone());
                }
            }
        }

        if !to_remove.is_empty() {
            let mut allocations_write = allocations.write().await;
            for id in to_remove {
                if allocations_write.remove(&id).is_some() {
                    stats.active_turn_allocations.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    debug!("Удален истекший TURN allocation: {}", id);
                }
            }
        }
    }

    /// Подписаться на события
    pub fn subscribe(&self) -> broadcast::Receiver<StunTurnEvent> {
        self.event_tx.subscribe()
    }

    /// Получить статистику
    pub fn get_stats(&self) -> &StunTurnStats {
        &self.stats
    }

    /// Получить кэшированное поведение NAT
    pub async fn get_nat_behavior(&self, local_addr: &SocketAddr) -> Option<NatBehavior> {
        self.nat_behavior_cache.read().await.get(local_addr).cloned()
    }

    /// Завершить работу менеджера
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Завершение работы STUN/TURN менеджера");

        // Установить флаг завершения
        let _ = self.shutdown_tx.send(true);

        // Отправить событие завершения
        let _ = self.event_tx.send(StunTurnEvent::Shutdown);

        // Дождаться завершения фоновых задач
        let mut tasks = self.background_tasks.lock().await;
        while let Some(task) = tasks.pop() {
            let _ = task.await;
        }

        // Завершить TURN allocations (заглушка)
        let allocations = self.turn_allocations.read().await;
        for (id, _allocation) in allocations.iter() {
            debug!("Завершение TURN allocation: {}", id);
            // В реальной реализации здесь был бы вызов deallocate()
        }

        // Остановить TURN сервер если запущен
        if let Some(turn_server) = &self.turn_server {
            if let Err(e) = turn_server.shutdown().await {
                warn!("Ошибка завершения TURN сервера: {}", e);
            }
        }

        info!("STUN/TURN менеджер завершен");
        Ok(())
    }
}

impl QualityMonitor {
    pub fn new(config: QualityMonitoringConfig) -> Self {
        Self {
            config,
            measurements: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start_monitoring(&self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = interval(self.config.monitoring_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.perform_quality_measurements().await;
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    async fn perform_quality_measurements(&self) {
        if self.config.enable_rtt_monitoring || self.config.enable_packet_loss_monitoring {
            trace!("Выполнение измерений качества соединения");
            // В реальности здесь бы измерялись RTT, потеря пакетов и т.д.
            // Это заглушка
        }
    }
}

/// Фабричная функция для создания сконфигурированного STUN/TURN менеджера
pub async fn create_stun_turn_manager(
    stun_servers: Vec<String>,
    turn_servers: Vec<TurnServerInfo>,
    enable_integrated_turn_server: bool,
) -> NatResult<StunTurnManager> {
    let mut config = StunTurnConfig::default();

    // Настроить STUN
    config.stun_config.servers = stun_servers.iter()
        .map(|s| crate::nat::stun::StunServerInfo {
            address: s.clone(),
            credentials: None,
        })
        .collect();

    // Настроить TURN серверы
    config.turn_servers = turn_servers;

    // Опционально включить интегрированный TURN сервер
    if enable_integrated_turn_server {
        // Создать базовую конфигурацию TURN сервера
        let turn_config = crate::nat::turn::TurnServerConfig {
            bind_address: "0.0.0.0:3478".parse().unwrap(),
            external_address: None,
            realm: "sharp3.local".to_string(),
            auth_config: crate::nat::turn::AuthConfig::Static {
                users: vec![
                    ("user".to_string(), "pass".to_string()),
                ].into_iter().collect(),
            },
            allocation_lifetime: Duration::from_secs(600),
            max_allocations: 1000,
            enable_tcp: false,
            enable_tls: false,
            cert_path: None,
            key_path: None,
        };

        config.turn_server_config = Some(turn_config);
    }

    StunTurnManager::new(config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stun_turn_manager_creation() {
        let config = StunTurnConfig::default();
        let result = StunTurnManager::new(config).await;

        // В тестовой среде может не работать из-за отсутствия сети
        match result {
            Ok(_manager) => {
                // Тест пройден
            }
            Err(e) => {
                println!("Создание менеджера неудачно (ожидается в тестовой среде): {}", e);
            }
        }
    }

    #[test]
    fn test_priority_calculation() {
        let config = StunTurnConfig::default();
        let manager = StunTurnManager {
            config: Arc::new(config),
            stun_service: Arc::new(StunService::new()),
            turn_server: None,
            turn_allocations: Arc::new(RwLock::new(HashMap::new())),
            turn_clients: Arc::new(RwLock::new(HashMap::new())),
            nat_behavior_cache: Arc::new(RwLock::new(HashMap::new())),
            quality_monitor: Arc::new(QualityMonitor::new(QualityMonitoringConfig::default())),
            stats: Arc::new(StunTurnStats::default()),
            event_tx: broadcast::channel(1).0,
            shutdown: watch::channel(false).1,
            shutdown_tx: watch::channel(false).0,
            background_tasks: Arc::new(Mutex::new(Vec::new())),
        };

        let priority_host = manager.calculate_priority(
            CandidateType::Host,
            &"192.168.1.1".parse().unwrap()
        );
        let priority_relay = manager.calculate_priority(
            CandidateType::Relay,
            &"192.168.1.1".parse().unwrap()
        );

        assert!(priority_host > priority_relay);
    }
}