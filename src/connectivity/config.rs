// src/connectivity/config.rs
//! Конфигурация для системы connectivity

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Главная конфигурация connectivity системы
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityConfig {
    /// ICE конфигурация (WebRTC)
    pub ice: IceConfig,

    /// libp2p fallback конфигурация
    pub libp2p: LibP2pConfig,

    /// Relay серверы конфигурация
    pub relay: RelayConfig,

    /// NAT router pools конфигурация
    pub router_pools: RouterPoolsConfig,

    /// UPnP конфигурация
    pub upnp: UpnpConfig,

    /// Общие настройки connectivity
    pub general: GeneralConfig,
}

/// ICE конфигурация для WebRTC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceConfig {
    /// STUN серверы для определения публичного адреса
    pub stun_servers: Vec<String>,

    /// TURN серверы для relay
    pub turn_servers: Vec<TurnServer>,

    /// Роль в ICE negotiation
    pub controlling_role: Option<bool>,

    /// Включить trickle ICE (постепенный обмен кандидатами)
    pub trickle_ice: bool,

    /// Максимальное время сбора кандидатов
    pub gathering_timeout: Duration,

    /// Максимальное время connectivity checks
    pub connectivity_timeout: Duration,

    /// Интервал между connectivity checks
    pub check_interval: Duration,

    /// Максимальное количество пар для проверки
    pub max_candidate_pairs: usize,

    /// Включить поддержку IPv6
    pub enable_ipv6: bool,

    /// Включить host кандидатов
    pub enable_host_candidates: bool,

    /// Включить server reflexive кандидатов
    pub enable_srflx_candidates: bool,

    /// Включить relay кандидатов
    pub enable_relay_candidates: bool,

    /// Приоритеты для разных типов кандидатов
    pub candidate_priorities: CandidatePriorities,
}

/// TURN сервер конфигурация
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServer {
    /// URL сервера (turn:host:port или turns:host:port для TLS)
    pub url: String,

    /// Имя пользователя
    pub username: String,

    /// Пароль или credential
    pub credential: String,

    /// Тип credential (password или token)
    pub credential_type: TurnCredentialType,

    /// Поддерживаемые транспорты
    pub transport: TurnTransport,

    /// Приоритет сервера (выше = предпочтительнее)
    pub priority: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TurnCredentialType {
    Password,
    Token,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TurnTransport {
    Udp,
    Tcp,
    Tls,
}

/// Приоритеты для разных типов кандидатов
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePriorities {
    pub host: u16,
    pub server_reflexive: u16,
    pub peer_reflexive: u16,
    pub relay: u16,
    pub router_pool: u16,
}

/// libp2p fallback конфигурация
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibP2pConfig {
    /// Включить libp2p fallback
    pub enabled: bool,

    /// Bootnodes для подключения к сети
    pub bootnodes: Vec<String>,

    /// Локальный порт для прослушивания
    pub listen_port: Option<u16>,

    /// Таймаут для autonat проверки
    pub autonat_timeout: Duration,

    /// Интервал между retry попытками
    pub retry_interval: Duration,

    /// Максимальное количество retry
    pub max_retries: u32,

    /// Включить mdns discovery
    pub enable_mdns: bool,

    /// Включить hole punching
    pub enable_hole_punching: bool,
}

/// Конфигурация relay серверов
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Публичные TURN серверы как fallback
    pub public_turn_servers: Vec<String>,

    /// Пользовательские SHARP relay серверы
    pub sharp_relay_servers: Vec<SharpRelayServer>,

    /// Включить шифрование заголовков
    pub enable_header_encryption: bool,

    /// Алгоритм шифрования заголовков
    pub header_encryption_algorithm: HeaderEncryptionAlgorithm,

    /// Таймаут подключения к relay
    pub connection_timeout: Duration,

    /// Heartbeat интервал для поддержания соединения
    pub heartbeat_interval: Duration,

    /// Максимальное время использования relay
    pub max_relay_time: Duration,
}

/// SHARP relay сервер
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharpRelayServer {
    /// Адрес сервера
    pub address: SocketAddr,

    /// Поддерживает ли шифрование заголовков
    pub supports_header_encryption: bool,

    /// Максимальная пропускная способность (bytes/sec)
    pub bandwidth_limit: Option<u64>,

    /// Регион сервера
    pub region: Option<String>,

    /// Приоритет (выше = предпочтительнее)
    pub priority: u8,

    /// Аутентификация (если требуется)
    pub auth_token: Option<String>,
}

/// Алгоритм шифрования заголовков
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HeaderEncryptionAlgorithm {
    ChaCha20Poly1305,
    AesGcm256,
    AesGcm128,
}

/// Конфигурация NAT router pools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterPoolsConfig {
    /// Включить router pools
    pub enabled: bool,

    /// Путь к файлу с пулами роутеров
    pub pools_file: Option<PathBuf>,

    /// Встроенные пулы роутеров
    pub builtin_pools: Vec<RouterPool>,

    /// Максимальное количество роутеров для попытки
    pub max_routers_to_try: usize,

    /// Таймаут для проверки роутера
    pub router_check_timeout: Duration,

    /// Приоритет router pools относительно других методов
    pub priority: u8,
}

/// Пул NAT роутеров
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterPool {
    /// Название пула
    pub name: String,

    /// Описание пула
    pub description: Option<String>,

    /// Список адресов роутеров
    pub routers: Vec<SocketAddr>,

    /// Регион или ISP
    pub region: Option<String>,

    /// Приоритет пула
    pub priority: u8,

    /// Дополнительные метаданные
    pub metadata: HashMap<String, String>,
}

/// UPnP конфигурация (legacy support)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpnpConfig {
    /// Включить UPnP
    pub enabled: bool,

    /// Таймаут поиска gateway
    pub discovery_timeout: Duration,

    /// Время lease для port mapping
    pub lease_duration: u32,

    /// Диапазон портов для mapping
    pub port_range: (u16, u16),

    /// Максимальное количество попыток mapping
    pub max_mapping_attempts: u32,
}

/// Общие настройки connectivity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Общий таймаут для установления соединения
    pub connection_timeout: Duration,

    /// Включить hairpining detection
    pub enable_hairpining: bool,

    /// Агрессивность nomination (быстрее vs надежнее)
    pub nomination_strategy: NominationStrategy,

    /// Включить метрики и мониторинг
    pub enable_metrics: bool,

    /// Уровень логирования для connectivity
    pub log_level: String,

    /// Максимальное количество одновременных попыток
    pub max_concurrent_attempts: usize,

    /// Включить fallback механизмы
    pub enable_fallback: bool,

    /// Порядок попыток методов подключения
    pub connection_methods_order: Vec<ConnectionMethod>,
}

/// Стратегия nomination кандидатов
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NominationStrategy {
    /// Быстрая nomination первого работающего кандидата
    Aggressive,
    /// Ожидание нескольких кандидатов перед выбором лучшего
    Regular,
    /// Тестирование всех кандидатов перед выбором
    Conservative,
}

/// Методы подключения в порядке приоритета
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConnectionMethod {
    /// Прямое соединение (если возможно)
    Direct,
    /// WebRTC ICE
    Ice,
    /// UPnP port mapping
    Upnp,
    /// NAT router pools
    RouterPools,
    /// libp2p fallback
    LibP2p,
    /// TURN/SHARP relay
    Relay,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            ice: IceConfig::default(),
            libp2p: LibP2pConfig::default(),
            relay: RelayConfig::default(),
            router_pools: RouterPoolsConfig::default(),
            upnp: UpnpConfig::default(),
            general: GeneralConfig::default(),
        }
    }
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
                "stun:stun.cloudflare.com:3478".to_string(),
                "stun:stun.nextcloud.com:443".to_string(),
            ],
            turn_servers: vec![],
            controlling_role: None,
            trickle_ice: true,
            gathering_timeout: Duration::from_secs(10),
            connectivity_timeout: Duration::from_secs(30),
            check_interval: Duration::from_millis(50),
            max_candidate_pairs: 100,
            enable_ipv6: true,
            enable_host_candidates: true,
            enable_srflx_candidates: true,
            enable_relay_candidates: true,
            candidate_priorities: CandidatePriorities::default(),
        }
    }
}

impl Default for CandidatePriorities {
    fn default() -> Self {
        Self {
            host: 126,
            server_reflexive: 100,
            peer_reflexive: 110,
            relay: 0,
            router_pool: 90,
        }
    }
}

impl Default for LibP2pConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bootnodes: vec![],
            listen_port: None,
            autonat_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(5),
            max_retries: 3,
            enable_mdns: true,
            enable_hole_punching: true,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            public_turn_servers: vec![
                "turn:openrelay.metered.ca:80".to_string(),
                "turn:openrelay.metered.ca:443".to_string(),
            ],
            sharp_relay_servers: vec![],
            enable_header_encryption: true,
            header_encryption_algorithm: HeaderEncryptionAlgorithm::ChaCha20Poly1305,
            connection_timeout: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(30),
            max_relay_time: Duration::from_secs(3600), // 1 hour
        }
    }
}

impl Default for RouterPoolsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pools_file: Some(PathBuf::from("src/nat_router_pools.toml")),
            builtin_pools: vec![RouterPool {
                name: "common-home-routers".to_string(),
                description: Some("Common home router default gateways".to_string()),
                routers: vec![
                    "192.168.1.1:53".parse().unwrap(),
                    "192.168.0.1:53".parse().unwrap(),
                    "10.0.0.1:53".parse().unwrap(),
                    "172.16.0.1:53".parse().unwrap(),
                ],
                region: Some("global".to_string()),
                priority: 50,
                metadata: HashMap::new(),
            }],
            max_routers_to_try: 5,
            router_check_timeout: Duration::from_secs(2),
            priority: 90,
        }
    }
}

impl Default for UpnpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            discovery_timeout: Duration::from_secs(5),
            lease_duration: 3600, // 1 hour
            port_range: (49152, 65535),
            max_mapping_attempts: 5,
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(60),
            enable_hairpining: true,
            nomination_strategy: NominationStrategy::Regular,
            enable_metrics: true,
            log_level: "info".to_string(),
            max_concurrent_attempts: 10,
            enable_fallback: true,
            connection_methods_order: vec![
                ConnectionMethod::Direct,
                ConnectionMethod::Ice,
                ConnectionMethod::Upnp,
                ConnectionMethod::RouterPools,
                ConnectionMethod::LibP2p,
                ConnectionMethod::Relay,
            ],
        }
    }
}

impl ConnectivityConfig {
    /// Загрузка конфигурации из TOML файла
    #[cfg(feature = "nat-router-pools")]
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Сохранение конфигурации в TOML файл
    #[cfg(feature = "nat-router-pools")]
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> anyhow::Result<()> {
        let toml_content = toml::to_string_pretty(self)?;
        std::fs::write(path, toml_content)?;
        Ok(())
    }

    /// Создание конфигурации для testing окружения
    pub fn for_testing() -> Self {
        let mut config = Self::default();

        // Уменьшаем таймауты для быстрого тестирования
        config.ice.gathering_timeout = Duration::from_secs(3);
        config.ice.connectivity_timeout = Duration::from_secs(10);
        config.general.connection_timeout = Duration::from_secs(15);

        // Отключаем некоторые медленные методы
        config.upnp.enabled = false;
        config.router_pools.enabled = false;

        // Агрессивная nomination для быстроты
        config.general.nomination_strategy = NominationStrategy::Aggressive;

        config
    }

    /// Создание конфигурации для production
    pub fn for_production() -> Self {
        let mut config = Self::default();

        // Увеличиваем таймауты для надежности
        config.ice.gathering_timeout = Duration::from_secs(15);
        config.ice.connectivity_timeout = Duration::from_secs(45);
        config.general.connection_timeout = Duration::from_secs(90);

        // Консервативная nomination для надежности
        config.general.nomination_strategy = NominationStrategy::Conservative;

        // Включаем все методы
        config.router_pools.enabled = true;
        config.upnp.enabled = true;
        config.libp2p.enabled = true;

        config
    }

    /// Оптимизация конфигурации для symmetric NAT
    pub fn optimize_for_symmetric_nat(&mut self) {
        // Увеличиваем приоритет relay методов
        self.ice.candidate_priorities.relay = 50;
        self.router_pools.priority = 120;

        // Включаем более агрессивные методы
        self.relay.enable_header_encryption = true;
        self.libp2p.enable_hole_punching = true;

        // Изменяем порядок методов для symmetric NAT
        self.general.connection_methods_order = vec![
            ConnectionMethod::RouterPools,
            ConnectionMethod::Relay,
            ConnectionMethod::LibP2p,
            ConnectionMethod::Ice,
            ConnectionMethod::Upnp,
            ConnectionMethod::Direct,
        ];
    }

    /// Валидация конфигурации
    pub fn validate(&self) -> anyhow::Result<()> {
        // Проверяем STUN серверы
        if self.ice.stun_servers.is_empty() {
            return Err(anyhow::anyhow!(
                "At least one STUN server must be configured"
            ));
        }

        // Проверяем таймауты
        if self.general.connection_timeout < Duration::from_secs(10) {
            return Err(anyhow::anyhow!(
                "Connection timeout too small (minimum 10 seconds)"
            ));
        }

        // Проверяем приоритеты
        if self.ice.candidate_priorities.host == 0 {
            return Err(anyhow::anyhow!("Host candidate priority cannot be zero"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = ConnectivityConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_symmetric_nat_optimization() {
        let mut config = ConnectivityConfig::default();
        config.optimize_for_symmetric_nat();

        assert_eq!(
            config.general.connection_methods_order[0],
            ConnectionMethod::RouterPools
        );
        assert!(config.ice.candidate_priorities.relay > 0);
    }

    #[test]
    fn test_testing_config() {
        let config = ConnectivityConfig::for_testing();
        assert!(config.ice.gathering_timeout < Duration::from_secs(5));
        assert_eq!(
            config.general.nomination_strategy,
            NominationStrategy::Aggressive
        );
    }

    #[cfg(feature = "nat-router-pools")]
    #[test]
    fn test_config_serialization() {
        let config = ConnectivityConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: ConnectivityConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.ice.stun_servers, deserialized.ice.stun_servers);
    }
}
