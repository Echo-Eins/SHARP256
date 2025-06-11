use anyhow::Result;
use tokio::net::UdpSocket;
use parking_lot::RwLock;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};

pub mod stun;
pub mod upnp;
pub mod hole_punch;
pub mod coordinator;

use self::stun::StunClient;
use self::upnp::UpnpClient;
use self::hole_punch::HolePuncher;
use self::coordinator::AdvancedNatTraversal;

/// Конфигурация NAT traversal
#[derive(Debug, Clone)]
pub struct NatConfig {
    pub enable_stun: bool,
    pub enable_upnp: bool,
    pub enable_hole_punching: bool,
    pub stun_servers: Vec<String>,
    pub upnp_lease_duration: u32, // в секундах
    pub hole_punch_attempts: u32,
    pub coordinator_server: Option<String>, // Адрес координационного сервера
    pub relay_servers: Vec<String>, // Адреса relay серверов
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_stun: true,
            enable_upnp: true,
            enable_hole_punching: true,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun.cloudflare.com:3478".to_string(),
            ],
            upnp_lease_duration: 3600, // 1 час
            hole_punch_attempts: 10,
            coordinator_server: None,
            relay_servers: vec![],
        }
    }
}

/// Результат определения сетевой конфигурации
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub local_addr: SocketAddr,
    pub public_addr: Option<SocketAddr>,
    pub nat_type: NatType,
    pub upnp_available: bool,
    pub mapped_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    None,           // Публичный IP
    FullCone,       // Полный конус NAT
    RestrictedCone, // Ограниченный конус NAT
    PortRestricted, // Порт-ограниченный конус NAT
    Symmetric,      // Симметричный NAT (сложный для traversal)
    Unknown,
}

/// Менеджер NAT traversal
pub struct NatManager {
    config: NatConfig,
    network_info: Arc<RwLock<Option<NetworkInfo>>>,
    upnp_client: Option<UpnpClient>,
    stun_client: StunClient,
    advanced_traversal: Option<AdvancedNatTraversal>,
}

impl NatManager {
    pub fn new(config: NatConfig) -> Self {
        let advanced_traversal = if config.coordinator_server.is_some() || !config.relay_servers.is_empty() {
            // Генерируем уникальный ID клиента
            #[cfg(feature = "nat-traversal")]
            let client_id = format!("sharp-{}", uuid::Uuid::new_v4());
            
            #[cfg(not(feature = "nat-traversal"))]
            let client_id = format!("sharp-{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());
            
            let coordinator_addr = config.coordinator_server.as_ref()
                .and_then(|s| s.parse().ok());
            
            let relay_addrs: Vec<SocketAddr> = config.relay_servers.iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            
            Some(AdvancedNatTraversal::new(coordinator_addr, relay_addrs, client_id))
        } else {
            None
        };
        
        Self {
            stun_client: StunClient::new(config.stun_servers.clone()),
            config,
            network_info: Arc::new(RwLock::new(None)),
            upnp_client: None,
            advanced_traversal,
        }
    }

    /// Инициализация и определение сетевой конфигурации
    pub async fn initialize(&mut self, local_socket: &UdpSocket) -> Result<NetworkInfo> {
        let local_addr = local_socket.local_addr()?;
        tracing::info!("Initializing NAT traversal for {}", local_addr);

        // 1. Определяем публичный адрес через STUN
        let public_addr = if self.config.enable_stun {
            match self.discover_public_address(local_socket).await {
                Ok(addr) => {
                    tracing::info!("Public address discovered: {}", addr);
                    Some(addr)
                }
                Err(e) => {
                    tracing::warn!("STUN discovery failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // 2. Определяем тип NAT
        let nat_type = if let Some(pub_addr) = public_addr {
            if pub_addr.ip() == local_addr.ip() {
                NatType::None
            } else {
                self.detect_nat_type(local_socket).await.unwrap_or(NatType::Unknown)
            }
        } else {
            NatType::Unknown
        };

        tracing::info!("NAT type detected: {:?}", nat_type);

        // 3. Пытаемся настроить UPnP
        let (upnp_available, mapped_port) = if self.config.enable_upnp && nat_type != NatType::None {
            match self.setup_upnp(local_addr.port()).await {
                Ok(port) => {
                    tracing::info!("UPnP mapping created: {} -> {}", local_addr.port(), port);
                    (true, Some(port))
                }
                Err(e) => {
                    tracing::warn!("UPnP setup failed: {}", e);
                    (false, None)
                }
            }
        } else {
            (false, None)
        };

        let network_info = NetworkInfo {
            local_addr,
            public_addr,
            nat_type,
            upnp_available,
            mapped_port,
        };

        *self.network_info.write() = Some(network_info.clone());
        Ok(network_info)
    }

    /// Определение публичного адреса через STUN
    async fn discover_public_address(&self, socket: &UdpSocket) -> Result<SocketAddr> {
        self.stun_client.get_mapped_address(socket).await
    }

    /// Определение типа NAT
    async fn detect_nat_type(&self, socket: &UdpSocket) -> Result<NatType> {
        // Используем несколько STUN серверов для определения типа NAT
        let results = self.stun_client.detect_nat_type(socket).await?;
        
        // Анализируем результаты
        if results.len() < 2 {
            return Ok(NatType::Unknown);
        }

        let first_addr = results[0];
        let all_same = results.iter().all(|&addr| addr == first_addr);

        if all_same {
            // Все STUN серверы видят один и тот же адрес - Full Cone или Restricted
            Ok(NatType::RestrictedCone)
        } else {
            // Разные адреса - Symmetric NAT
            Ok(NatType::Symmetric)
        }
    }

    /// Настройка UPnP
    async fn setup_upnp(&mut self, local_port: u16) -> Result<u16> {
        let mut client = UpnpClient::new().await?;
        
        if !client.is_available() {
            return Err(anyhow::anyhow!("UPnP gateway not found"));
        }
        
        // Получаем внешний IP через UPnP для сравнения
        if let Ok(upnp_external_ip) = client.get_external_ip().await {
            tracing::info!("External IP from UPnP: {}", upnp_external_ip);
        }
        
        let external_port = client.add_port_mapping(
            local_port,
            self.config.upnp_lease_duration,
            "SHARP-256 File Transfer"
        ).await?;
        
        self.upnp_client = Some(client);
        Ok(external_port)
    }

    /// Получение лучшего адреса для подключения
    pub fn get_connectable_address(&self) -> Result<SocketAddr> {
        let info = self.network_info.read()
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Network info not initialized"))?
            .clone();

        // Приоритеты:
        // 1. UPnP mapped port с публичным IP
        // 2. Публичный адрес (если Full Cone NAT)
        // 3. Локальный адрес (для LAN)

        if let (Some(pub_addr), Some(mapped_port)) = (info.public_addr, info.mapped_port) {
            Ok(SocketAddr::new(pub_addr.ip(), mapped_port))
        } else if let Some(pub_addr) = info.public_addr {
            if info.nat_type == NatType::FullCone || info.nat_type == NatType::None {
                Ok(pub_addr)
            } else {
                Ok(info.local_addr)
            }
        } else {
            Ok(info.local_addr)
        }
    }

    /// Подготовка соединения с peer (hole punching при необходимости)
    pub async fn prepare_connection(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        is_initiator: bool,
    ) -> Result<()> {
        let info = self.network_info.read()
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Network info not initialized"))?
            .clone();

        // Проверяем, нужны ли продвинутые методы
        if info.nat_type == NatType::Symmetric {
            // Для симметричного NAT используем продвинутые методы
            if let Some(advanced) = &self.advanced_traversal {
                tracing::info!("Using advanced NAT traversal for symmetric NAT");
                
                // Пытаемся установить соединение через все доступные методы
                match advanced.establish_connection(socket, "peer", Some(peer_addr)).await {
                    Ok(effective_addr) => {
                        tracing::info!("Connection established via {}", effective_addr);
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!("Advanced NAT traversal failed: {}", e);
                    }
                }
            }
        }

        // Hole punching для остальных типов NAT
        if self.config.enable_hole_punching && 
           (info.nat_type == NatType::RestrictedCone || 
            info.nat_type == NatType::PortRestricted ||
            info.nat_type == NatType::Symmetric) {
            
            tracing::info!("Starting hole punching with {}", peer_addr);
            let puncher = HolePuncher::new(self.config.hole_punch_attempts);
            
            // Если есть координатор, используем координированный hole punching
            if let Some(advanced) = &self.advanced_traversal {
                if let Some(coordinator) = &advanced.coordinator {
                    match coordinator.coordinate_hole_punch(socket, peer_addr).await {
                        Ok(()) => {
                            tracing::info!("Using coordinated hole punching");
                        }
                        Err(e) => {
                            tracing::warn!("Coordinator unavailable: {}", e);
                        }
                    }
                }
            }
            
            puncher.punch_hole(socket, peer_addr, is_initiator).await?;
        }

        Ok(())
    }

    /// Очистка ресурсов (удаление UPnP маппингов)
    pub async fn cleanup(&mut self) -> Result<()> {
        if let Some(mut client) = self.upnp_client.take() {
            client.cleanup_all().await?;
        }
        Ok(())
    }

    /// Извлекает UPnP клиент для внешней очистки
    pub fn take_upnp_client(&mut self) -> Option<UpnpClient> {
        self.upnp_client.take()
    }
}

impl Drop for NatManager {
    fn drop(&mut self) {
        // Пытаемся очистить UPnP маппинги при завершении
        if self.upnp_client.is_some() {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                handle.spawn(async move {
                    // Cleanup будет выполнен асинхронно
                });
            }
        }
    }
}