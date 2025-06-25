// src/nat/turn/mod.rs (дополнения для совместимости)
//! Дополнения к TURN модулю для совместимости с новыми менеджерами

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use serde::{Serialize, Deserialize};

use crate::nat::error::{NatError, NatResult};

// Добавить недостающие типы для совместимости

/// Конфигурация TURN сервера (базовая)
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    /// Адрес для привязки сервера
    pub bind_address: SocketAddr,

    /// Внешний адрес (если отличается от bind_address)
    pub external_address: Option<SocketAddr>,

    /// Realm для аутентификации
    pub realm: String,

    /// Конфигурация аутентификации
    pub auth_config: AuthConfig,

    /// Время жизни allocation по умолчанию
    pub allocation_lifetime: Duration,

    /// Максимальное количество allocations
    pub max_allocations: usize,

    /// Включить TCP поддержку
    pub enable_tcp: bool,

    /// Включить TLS поддержку
    pub enable_tls: bool,

    /// Путь к сертификату (для TLS)
    pub cert_path: Option<String>,

    /// Путь к ключу (для TLS)
    pub key_path: Option<String>,
}

/// Конфигурация аутентификации
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// Статические пользователи
    Static {
        users: HashMap<String, String>, // username -> password
    },
    /// Внешний провайдер аутентификации
    External {
        endpoint: String,
        timeout: Duration,
    },
    /// Отключить аутентификацию (только для тестирования)
    Disabled,
}

/// TURN клиент
pub struct TurnClient {
    server_url: String,
    state: Arc<tokio::sync::RwLock<TurnClientState>>,
}

/// Состояние TURN клиента
#[derive(Debug)]
struct TurnClientState {
    connected: bool,
    allocations: HashMap<String, TurnAllocation>,
}

/// TURN allocation
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    pub relay_address: SocketAddr,
    pub allocated_at: Instant,
    pub expires_at: Instant,
}

/// TURN сервер (заглушка)
pub struct TurnServer {
    config: TurnServerConfig,
    running: Arc<tokio::sync::RwLock<bool>>,
}

/// Учетные данные TURN
#[derive(Debug, Clone)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
}

/// Состояние allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationState {
    /// Allocation запрошен
    Requested,
    /// Allocation активен
    Active,
    /// Allocation истекает
    Expiring,
    /// Allocation истек
    Expired,
    /// Allocation неудачен
    Failed,
}

/// Адрес relay
#[derive(Debug, Clone)]
pub struct RelayAddress {
    pub address: SocketAddr,
    pub allocated_at: Instant,
    pub expires_at: Instant,
}

impl TurnClient {
    /// Создать новый TURN клиент
    pub async fn new(server_url: &str) -> NatResult<Self> {
        let state = TurnClientState {
            connected: false,
            allocations: HashMap::new(),
        };

        Ok(Self {
            server_url: server_url.to_string(),
            state: Arc::new(tokio::sync::RwLock::new(state)),
        })
    }

    /// Выполнить allocation (заглушка)
    pub async fn allocate(
        &self,
        socket: Arc<UdpSocket>,
        credentials: TurnCredentials,
        lifetime: Duration,
    ) -> NatResult<TurnAllocation> {
        tracing::debug!("Выполнение TURN allocation для {}", self.server_url);

        // В реальной реализации здесь был бы полный TURN протокол
        // Пока что возвращаем ошибку или фиктивные данные

        // Для совместимости создаем фиктивный allocation
        let relay_address = socket.local_addr()
            .map_err(|e| NatError::Network(format!("Не удалось получить локальный адрес: {}", e)))?;

        let allocation = TurnAllocation {
            relay_address,
            allocated_at: Instant::now(),
            expires_at: Instant::now() + lifetime,
        };

        // Сохранить в состоянии
        {
            let mut state = self.state.write().await;
            let allocation_id = format!("{}:{}", relay_address.ip(), relay_address.port());
            state.allocations.insert(allocation_id, allocation.clone());
            state.connected = true;
        }

        Ok(allocation)
    }

    /// Освободить allocation (заглушка)
    pub async fn deallocate(&self) -> NatResult<()> {
        tracing::debug!("Освобождение TURN allocations для {}", self.server_url);

        let mut state = self.state.write().await;
        state.allocations.clear();
        state.connected = false;

        Ok(())
    }

    /// Получить состояние клиента
    pub async fn is_connected(&self) -> bool {
        self.state.read().await.connected
    }

    /// Получить активные allocations
    pub async fn get_allocations(&self) -> Vec<TurnAllocation> {
        self.state.read().await.allocations.values().cloned().collect()
    }
}

impl TurnServer {
    /// Создать новый TURN сервер
    pub async fn new(config: TurnServerConfig) -> NatResult<Self> {
        tracing::info!("Создание TURN сервера на {}", config.bind_address);

        Ok(Self {
            config,
            running: Arc::new(tokio::sync::RwLock::new(false)),
        })
    }

    /// Запустить TURN сервер (заглушка)
    pub async fn start(&self) -> NatResult<()> {
        tracing::info!("Запуск TURN сервера на {}", self.config.bind_address);

        *self.running.write().await = true;

        // В реальной реализации здесь был бы запуск сервера
        // Пока что просто имитируем успешный запуск
        tracing::info!("TURN сервер запущен (заглушка)");

        Ok(())
    }

    /// Остановить TURN сервер
    pub async fn shutdown(&self) -> NatResult<()> {
        tracing::info!("Остановка TURN сервера");

        *self.running.write().await = false;

        // В реальной реализации здесь была бы корректная остановка
        tracing::info!("TURN сервер остановлен");

        Ok(())
    }

    /// Проверить, запущен ли сервер
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Получить конфигурацию сервера
    pub fn get_config(&self) -> &TurnServerConfig {
        &self.config
    }

    /// Получить статистику сервера (заглушка)
    pub async fn get_stats(&self) -> TurnServerStats {
        TurnServerStats {
            active_allocations: 0,
            total_allocations: 0,
            bytes_relayed: 0,
            uptime: Duration::ZERO,
        }
    }
}

/// Статистика TURN сервера
#[derive(Debug, Clone)]
pub struct TurnServerStats {
    pub active_allocations: u64,
    pub total_allocations: u64,
    pub bytes_relayed: u64,
    pub uptime: Duration,
}

impl Default for TurnServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:3478".parse().unwrap(),
            external_address: None,
            realm: "turn.local".to_string(),
            auth_config: AuthConfig::Static {
                users: HashMap::new(),
            },
            allocation_lifetime: Duration::from_secs(600),
            max_allocations: 1000,
            enable_tcp: false,
            enable_tls: false,
            cert_path: None,
            key_path: None,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self::Static {
            users: HashMap::new(),
        }
    }
}

/// Создать конфигурацию TURN сервера по умолчанию
pub fn create_default_config(bind_addr: &str, external_addr: &str) -> NatResult<TurnServerConfig> {
    let bind_address = bind_addr.parse()
        .map_err(|e| NatError::Configuration(format!("Неверный адрес привязки: {}", e)))?;

    let external_address = if external_addr.is_empty() {
        None
    } else {
        Some(external_addr.parse()
            .map_err(|e| NatError::Configuration(format!("Неверный внешний адрес: {}", e)))?)
    };

    let mut users = HashMap::new();
    users.insert("user".to_string(), "pass".to_string());

    Ok(TurnServerConfig {
        bind_address,
        external_address,
        realm: "sharp3.local".to_string(),
        auth_config: AuthConfig::Static { users },
        allocation_lifetime: Duration::from_secs(600),
        max_allocations: 1000,
        enable_tcp: false,
        enable_tls: false,
        cert_path: None,
        key_path: None,
    })
}

/// Создать тестовые учетные данные TURN
pub fn create_test_credentials() -> TurnCredentials {
    TurnCredentials {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        realm: Some("test.local".to_string()),
    }
}

/// Проверить конфигурацию TURN сервера
pub fn validate_turn_config(config: &TurnServerConfig) -> NatResult<()> {
    // Проверить адрес привязки
    if config.bind_address.port() == 0 {
        return Err(NatError::Configuration("Порт привязки не может быть 0".to_string()));
    }

    // Проверить время жизни allocation
    if config.allocation_lifetime < Duration::from_secs(30) {
        return Err(NatError::Configuration("Время жизни allocation слишком короткое".to_string()));
    }

    if config.allocation_lifetime > Duration::from_secs(86400) {
        return Err(NatError::Configuration("Время жизни allocation слишком длинное".to_string()));
    }

    // Проверить максимальное количество allocations
    if config.max_allocations == 0 {
        return Err(NatError::Configuration("Максимальное количество allocations не может быть 0".to_string()));
    }

    // Проверить конфигурацию аутентификации
    match &config.auth_config {
        AuthConfig::Static { users } => {
            if users.is_empty() {
                tracing::warn!("Нет пользователей для статической аутентификации");
            }
        }
        AuthConfig::External { endpoint, .. } => {
            if endpoint.is_empty() {
                return Err(NatError::Configuration("Endpoint для внешней аутентификации не может быть пустым".to_string()));
            }
        }
        AuthConfig::Disabled => {
            tracing::warn!("Аутентификация отключена - использовать только для тестирования");
        }
    }

    // Проверить TLS конфигурацию
    if config.enable_tls {
        if config.cert_path.is_none() || config.key_path.is_none() {
            return Err(NatError::Configuration("TLS включен, но не указаны пути к сертификату или ключу".to_string()));
        }
    }

    Ok(())
}

// Дополнительный модуль для сервера
pub mod server {
    pub use super::*;

    /// Создать базовую конфигурацию TURN сервера
    pub fn create_default_config(bind_addr: &str, external_addr: &str) -> crate::nat::error::NatResult<TurnServerConfig> {
        super::create_default_config(bind_addr, external_addr)
    }

    /// Экспорт типов для обратной совместимости
    pub use super::{TurnServerConfig, AuthConfig, TurnServer};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_turn_client_creation() {
        let client = TurnClient::new("turn:example.com:3478").await;
        assert!(client.is_ok());

        if let Ok(client) = client {
            assert!(!client.is_connected().await);
            assert!(client.get_allocations().await.is_empty());
        }
    }

    #[tokio::test]
    async fn test_turn_server_creation() {
        let config = TurnServerConfig::default();
        let server = TurnServer::new(config).await;
        assert!(server.is_ok());

        if let Ok(server) = server {
            assert!(!server.is_running().await);
        }
    }

    #[test]
    fn test_config_validation() {
        let valid_config = TurnServerConfig::default();
        assert!(validate_turn_config(&valid_config).is_ok());

        let mut invalid_config = TurnServerConfig::default();
        invalid_config.allocation_lifetime = Duration::from_secs(10); // Слишком короткое
        assert!(validate_turn_config(&invalid_config).is_err());
    }

    #[test]
    fn test_default_config_creation() {
        let config = create_default_config("0.0.0.0:3478", "203.0.113.1").unwrap();
        assert_eq!(config.bind_address.port(), 3478);
        assert!(config.external_address.is_some());
        assert_eq!(config.realm, "sharp3.local");
    }

    #[test]
    fn test_credentials_creation() {
        let creds = create_test_credentials();
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password, "testpass");
        assert!(creds.realm.is_some());
    }
}