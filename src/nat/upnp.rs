use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use igd::{PortMappingProtocol, SearchOptions};
use parking_lot::RwLock;
use std::sync::Arc;
use igd::aio::{search_gateway, Gateway};

/// UPnP клиент для управления port forwarding на роутере
pub struct UpnpClient {
    gateway: Option<Gateway>,
    local_ip: IpAddr,
    active_mappings: Arc<RwLock<Vec<PortMapping>>>,
}

#[derive(Debug, Clone)]
struct PortMapping {
    external_port: u16,
    internal_port: u16,
    protocol: PortMappingProtocol,
    description: String,
}

impl UpnpClient {
    /// Создание нового UPnP клиента с автоматическим обнаружением gateway
    pub async fn new() -> Result<Self> {
        // Определяем локальный IP
        let local_ip = Self::get_local_ip().await?;
        
        tracing::info!("Searching for UPnP gateway...");
        
        // Настройки поиска с таймаутом
        let search_options = SearchOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        
        // Ищем gateway
        match search_gateway(search_options).await {
            Ok(gateway) => {
                tracing::info!("UPnP gateway found: {}", gateway.addr);
                
                // Получаем информацию о внешнем IP
                if let Ok(external_ip) = gateway.get_external_ip().await {
                    tracing::info!("External IP via UPnP: {}", external_ip);
                }
                
                Ok(Self {
                    gateway: Some(gateway),
                    local_ip,
                    active_mappings: Arc::new(RwLock::new(Vec::new())),
                })
            }
            Err(e) => {
                tracing::warn!("No UPnP gateway found: {}", e);
                
                // Возвращаем клиент без gateway (будет работать как no-op)
                Ok(Self {
                    gateway: None,
                    local_ip,
                    active_mappings: Arc::new(RwLock::new(Vec::new())),
                })
            }
        }
    }

    /// Добавление port mapping
    pub async fn add_port_mapping(
        &mut self,
        local_port: u16,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16> {
        let gateway = self.gateway.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP gateway available"))?;

        // Пытаемся создать mapping на том же внешнем порту
        let mut external_port = local_port;
        let mut attempts = 0;
        
        loop {
            let local_addr = match self.local_ip {
                IpAddr::V4(ip) => std::net::SocketAddrV4::new(ip, local_port),
                IpAddr::V6(_) => {
                    return Err(anyhow::anyhow!("UPnP requires an IPv4 local address"));
                }
            };

            match gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    external_port,
                    local_addr,
                    lease_duration,
                    description,
                )
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        "UPnP port mapping created: {} -> {}:{} ({}s lease)",
                        external_port, self.local_ip, local_port, lease_duration
                    );
                    
                    // Сохраняем информацию о mapping
                    let mapping = PortMapping {
                        external_port,
                        internal_port: local_port,
                        protocol: PortMappingProtocol::UDP,
                        description: description.to_string(),
                    };
                    self.active_mappings.write().push(mapping);
                    
                    return Ok(external_port);
                }
                Err(e) => {
                    // Если порт занят, пробуем следующий
                    if attempts < 10 && e.to_string().contains("ConflictInMappingEntry") {
                        attempts += 1;
                        external_port = local_port + attempts;
                        tracing::debug!("Port {} busy, trying {}", external_port - 1, external_port);
                        continue;
                    }
                    
                    return Err(anyhow::anyhow!("Failed to create port mapping: {}", e));
                }
            }
        }
    }

    /// Удаление port mapping
    pub async fn remove_port_mapping(&mut self, external_port: u16) -> Result<()> {
        let gateway = self.gateway.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP gateway available"))?;

        // Ищем mapping в списке активных
        let mut mappings = self.active_mappings.write();
        if let Some(pos) = mappings.iter().position(|m| m.external_port == external_port) {
            let mapping = mappings.remove(pos);
            
            // Удаляем mapping на gateway
            match gateway.remove_port(mapping.protocol, external_port).await {
                Ok(()) => {
                    tracing::info!("UPnP port mapping removed: {}", external_port);
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to remove port mapping: {}", e);
                    // Не считаем это критической ошибкой
                    Ok(())
                }
            }
        } else {
            tracing::warn!("Port mapping {} not found in active list", external_port);
            Ok(())
        }
    }

    /// Обновление lease времени для всех активных mappings
    pub async fn refresh_mappings(&self, lease_duration: u32) -> Result<()> {
        let gateway = self.gateway.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP gateway available"))?;

        let mappings = self.active_mappings.read().clone();
        
        for mapping in mappings {
            let local_addr = match self.local_ip {
                IpAddr::V4(ip) => std::net::SocketAddrV4::new(ip, mapping.internal_port),
                IpAddr::V6(_) => {
                    tracing::warn!("Cannot refresh mapping for IPv6 local address");
                    continue;
                }
            };

            match gateway
                .add_port(
                    mapping.protocol,
                    mapping.external_port,
                    local_addr,
                    lease_duration,
                    &mapping.description,
                )
                .await
            {
                Ok(()) => {
                    tracing::debug!("Refreshed mapping for port {}", mapping.external_port);
                }
                Err(e) => {
                    tracing::warn!("Failed to refresh mapping for port {}: {}", 
                        mapping.external_port, e);
                }
            }
        }
        
        Ok(())
    }

    /// Получение внешнего IP адреса через UPnP
    pub async fn get_external_ip(&self) -> Result<IpAddr> {
        let gateway = self.gateway.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP gateway available"))?;

        let external_ip = gateway.get_external_ip().await
            .context("Failed to get external IP from UPnP gateway")?;
        
        Ok(IpAddr::V4(external_ip))
    }

    /// Очистка всех активных mappings
    pub async fn cleanup_all(&mut self) -> Result<()> {
        if let Some(gateway) = &self.gateway {
            let mappings = self.active_mappings.write().drain(..).collect::<Vec<_>>();
            
            for mapping in mappings {
                if let Err(e) = gateway.remove_port(mapping.protocol, mapping.external_port).await {
                    tracing::warn!("Failed to remove mapping {}: {}", mapping.external_port, e);
                }
            }
            
            tracing::info!("All UPnP port mappings cleaned up");
        }
        
        Ok(())
    }

    /// Проверка доступности UPnP
    pub fn is_available(&self) -> bool {
        self.gateway.is_some()
    }

    /// Получение локального IP адреса
    async fn get_local_ip() -> Result<IpAddr> {
        // Создаем временное соединение для определения локального IP
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect("8.8.8.8:80").await?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr.ip())
    }
}

impl Drop for UpnpClient {
    fn drop(&mut self) {
        // При удалении клиента пытаемся очистить mappings
        if !self.active_mappings.read().is_empty() {
            tracing::debug!("UPnP client dropping with active mappings");
            
            // Создаем задачу для асинхронной очистки
            let mappings = self.active_mappings.read().clone();
            if let Some(gateway) = self.gateway.clone() {
                tokio::spawn(async move {
                    for mapping in mappings {
                        let _ = gateway.remove_port(mapping.protocol, mapping.external_port).await;
                    }
                });
            }
        }
    }
}