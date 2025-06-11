use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use serde::{Deserialize, Serialize};

/// Клиент для координации P2P соединений через сервер
pub struct CoordinatorClient {
    server_addr: SocketAddr,
    client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CoordinatorMessage {
    Register {
        client_id: String,
        public_addr: Option<SocketAddr>,
    },
    RequestPeer {
        client_id: String,
        peer_id: String,
    },
    PeerInfo {
        peer_id: String,
        addresses: Vec<SocketAddr>, // Все известные адреса пира
        nat_type: String,
    },
    StartPunch {
        peer_addr: SocketAddr,
        token: String,
    },
}

impl CoordinatorClient {
    pub fn new(server_addr: SocketAddr, client_id: String) -> Self {
        Self {
            server_addr,
            client_id,
        }
    }

    /// Регистрация на координационном сервере
    pub async fn register(
        &self,
        socket: &UdpSocket,
        public_addr: Option<SocketAddr>,
    ) -> Result<()> {
        let msg = CoordinatorMessage::Register {
            client_id: self.client_id.clone(),
            public_addr,
        };
        
        let data = serde_json::to_vec(&msg)?;
        socket.send_to(&data, self.server_addr).await?;
        
        // Ждем подтверждение
        let mut buffer = vec![0u8; 1024];
        let (_size, _) = timeout(
            Duration::from_secs(5),
            socket.recv_from(&mut buffer)
        ).await??;
        
        tracing::info!("Registered with coordinator as {}", self.client_id);
        Ok(())
    }

    /// Запрос информации о пире для установления соединения
    pub async fn request_peer_info(
        &self,
        socket: &UdpSocket,
        peer_id: &str,
    ) -> Result<(Vec<SocketAddr>, String)> {
        let msg = CoordinatorMessage::RequestPeer {
            client_id: self.client_id.clone(),
            peer_id: peer_id.to_string(),
        };
        
        let data = serde_json::to_vec(&msg)?;
        socket.send_to(&data, self.server_addr).await?;
        
        // Получаем ответ
        let mut buffer = vec![0u8; 4096];
        let (size, _) = timeout(
            Duration::from_secs(10),
            socket.recv_from(&mut buffer)
        ).await??;
        
        let response: CoordinatorMessage = serde_json::from_slice(&buffer[..size])?;
        
        match response {
            CoordinatorMessage::PeerInfo { addresses, nat_type, .. } => {
                Ok((addresses, nat_type))
            }
            _ => Err(anyhow::anyhow!("Unexpected response from coordinator")),
        }
    }

    /// Координированный hole punching
    pub async fn coordinate_hole_punch(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // Генерируем токен для синхронизации
        let token: String = rand::random::<u64>().to_string();
        
        let msg = CoordinatorMessage::StartPunch {
            peer_addr,
            token: token.clone(),
        };
        
        let data = serde_json::to_vec(&msg)?;
        socket.send_to(&data, self.server_addr).await?;
        
        // Ждем сигнал начать punching
        let mut buffer = vec![0u8; 256];
        match timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) if addr == self.server_addr => {
                let response = String::from_utf8_lossy(&buffer[..size]);
                if response.contains(&token) {
                    tracing::info!("Starting coordinated hole punch");
                    return Ok(());
                }
            }
            _ => {}
        }
        Err(anyhow::anyhow!("Failed to coordinate hole punch"))
    }

}

/// Стратегия для обхода сложных NAT
pub struct AdvancedNatTraversal {
    pub coordinator: Option<CoordinatorClient>,
    pub relay_servers: Vec<SocketAddr>,
}

impl AdvancedNatTraversal {
    pub fn new(
        coordinator_addr: Option<SocketAddr>,
        relay_servers: Vec<SocketAddr>,
        client_id: String,
    ) -> Self {
        let coordinator = coordinator_addr.map(|addr| CoordinatorClient::new(addr, client_id));
        
        Self {
            coordinator,
            relay_servers,
        }
    }

    /// Попытка установить соединение через все доступные методы
    pub async fn establish_connection(
        &self,
        socket: &UdpSocket,
        peer_id: &str,
        peer_hint_addr: Option<SocketAddr>,
    ) -> Result<SocketAddr> {
        // 1. Если есть прямой адрес, пробуем его
        if let Some(addr) = peer_hint_addr {
            if self.try_direct_connection(socket, addr).await.is_ok() {
                return Ok(addr);
            }
        }
        
        // 2. Запрашиваем информацию через координатор
        if let Some(coordinator) = &self.coordinator {
            match coordinator.request_peer_info(socket, peer_id).await {
                Ok((addresses, nat_type)) => {
                    tracing::info!("Peer {} has NAT type: {}", peer_id, nat_type);
                    
                    // Пробуем все известные адреса
                    for addr in &addresses {
                        if self.try_direct_connection(socket, *addr).await.is_ok() {
                            return Ok(*addr);
                        }
                    }
                    
                    // Если прямое соединение не удалось, пробуем hole punching
                    if nat_type != "Symmetric" {
                        for addr in &addresses {
                            if coordinator.coordinate_hole_punch(socket, *addr).await.is_ok() {
                                return Ok(*addr);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get peer info: {}", e);
                }
            }
        }
        
        // 3. Последний вариант - relay сервер
        if !self.relay_servers.is_empty() {
            tracing::info!("Falling back to relay server");
            return Ok(self.relay_servers[0]); // Используем первый доступный relay
        }
        
        Err(anyhow::anyhow!("Failed to establish connection with peer"))
    }

    /// Попытка прямого соединения
    async fn try_direct_connection(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
    ) -> Result<()> {
        // Отправляем тестовый пакет
        socket.send_to(b"SHARP_PING", addr).await?;
        
        // Ждем ответ
        let mut buffer = vec![0u8; 256];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, recv_addr))) if recv_addr == addr => {
                let response = &buffer[..size];
                if response == b"SHARP_PONG" || response.starts_with(b"SHARP_") {
                    tracing::info!("Direct connection successful to {}", addr);
                    return Ok(());
                }
            }
            _ => {}
        }
        Err(anyhow::anyhow!("Direct connection to {} failed", addr))
    }
}