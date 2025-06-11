use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use parking_lot::RwLock;
use sharp_256::init_logging;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::interval;

#[derive(Parser, Debug)]
#[command(author, version, about = "SHARP-256 Relay Server", long_about = None)]
struct Args {
    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:5556")]
    bind: SocketAddr,
    
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Информация о клиенте
#[derive(Debug, Clone)]
struct ClientInfo {
    addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    last_seen: Instant,
}

/// Relay сервер для помощи в установлении P2P соединений
struct RelayServer {
    socket: Arc<UdpSocket>,
    clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
}

impl RelayServer {
    async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        
        Ok(Self {
            socket: Arc::new(socket),
            clients: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    async fn run(&self) -> Result<()> {
        let local_addr = self.socket.local_addr()?;
        println!("Relay server listening on {}", local_addr);
        println!("Clients can use this server for NAT traversal assistance\n");
        
        // Запускаем очистку устаревших клиентов
        let clients_clone = self.clients.clone();
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(30));
            loop {
                cleanup_interval.tick().await;
                Self::cleanup_inactive_clients(&clients_clone);
            }
        });
        
        let mut buffer = vec![0u8; 65536];
        
        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, addr)) => {
                    let data = &buffer[..size];
                    self.handle_message(data, addr).await;
                }
                Err(e) => {
                    tracing::error!("Socket error: {}", e);
                }
            }
        }
    }
    
    async fn handle_message(&self, data: &[u8], from: SocketAddr) {
        // Простой протокол для relay:
        // REGISTER:<client_id> - регистрация клиента
        // CONNECT:<client_id>:<peer_id> - запрос соединения
        // RELAY:<peer_id>:<data> - пересылка данных
        
        if let Ok(message) = std::str::from_utf8(data) {
            if message.starts_with("REGISTER:") {
                self.handle_register(message, from).await;
            } else if message.starts_with("CONNECT:") {
                self.handle_connect(message, from).await;
            } else if message.starts_with("GETINFO:") {
                self.handle_get_info(message, from).await;
            }
        } else if data.starts_with(b"RELAY:") {
            // Бинарные данные для пересылки
            self.handle_relay(data, from).await;
        }
    }
    
    async fn handle_register(&self, message: &str, from: SocketAddr) {
        if let Some(client_id) = message.strip_prefix("REGISTER:") {
            let mut clients = self.clients.write();
            clients.insert(client_id.to_string(), ClientInfo {
                addr: from,
                peer_addr: None,
                last_seen: Instant::now(),
            });
            
            tracing::info!("Client registered: {} from {}", client_id, from);
            
            // Отправляем подтверждение
            let response = format!("REGISTERED:{}", from);
            let _ = self.socket.send_to(response.as_bytes(), from).await;
        }
    }
    
    async fn handle_connect(&self, message: &str, from: SocketAddr) {
        if let Some(params) = message.strip_prefix("CONNECT:") {
            let parts: Vec<&str> = params.split(':').collect();
            if parts.len() == 2 {
                let client_id = parts[0];
                let peer_id = parts[1];
                
                let clients = self.clients.read();
                
                if let (Some(client), Some(peer)) = (clients.get(client_id), clients.get(peer_id)) {
                    if client.addr == from {
                        // Отправляем информацию о адресах обоим клиентам
                        let msg_to_client = format!("PEER_INFO:{}:{}", peer_id, peer.addr);
                        let msg_to_peer = format!("PEER_INFO:{}:{}", client_id, client.addr);
                        
                        let _ = self.socket.send_to(msg_to_client.as_bytes(), client.addr).await;
                        let _ = self.socket.send_to(msg_to_peer.as_bytes(), peer.addr).await;
                        
                        tracing::info!("Facilitating connection between {} and {}", client_id, peer_id);
                        
                        // Обновляем информацию о пирах
                        drop(clients);
                        let mut clients_mut = self.clients.write();
                        if let Some(client_mut) = clients_mut.get_mut(client_id) {
                            client_mut.peer_addr = Some(peer.addr);
                        }
                        if let Some(peer_mut) = clients_mut.get_mut(peer_id) {
                            peer_mut.peer_addr = Some(client.addr);
                        }
                    }
                }
            }
        }
    }
    
    async fn handle_get_info(&self, message: &str, from: SocketAddr) {
        if let Some(client_id) = message.strip_prefix("GETINFO:") {
            let clients = self.clients.read();
            
            if let Some(client) = clients.get(client_id) {
                let info = format!("INFO:{}:{}", client_id, client.addr);
                let _ = self.socket.send_to(info.as_bytes(), from).await;
            } else {
                let _ = self.socket.send_to(b"INFO:NOT_FOUND", from).await;
            }
        }
    }
    
    async fn handle_relay(&self, data: &[u8], from: SocketAddr) {
        // Формат: RELAY:<peer_id>:<binary_data>
        if data.len() > 6 && &data[..6] == b"RELAY:" {
            // Находим конец peer_id
            if let Some(colon_pos) = data[6..].iter().position(|&b| b == b':') {
                let peer_id_end = 6 + colon_pos;
                if let Ok(peer_id) = std::str::from_utf8(&data[6..peer_id_end]) {
                    let relay_data = &data[peer_id_end + 1..];
                    
                    let clients = self.clients.read();
                    if let Some(peer) = clients.get(peer_id) {
                        // Пересылаем данные
                        let _ = self.socket.send_to(relay_data, peer.addr).await;
                        tracing::debug!("Relayed {} bytes from {} to {}", relay_data.len(), from, peer.addr);
                    }
                }
            }
        }
    }
    
    fn cleanup_inactive_clients(clients: &Arc<RwLock<HashMap<String, ClientInfo>>>) {
        let mut clients = clients.write();
        let now = Instant::now();
        
        clients.retain(|id, info| {
            let inactive = now.duration_since(info.last_seen) < Duration::from_secs(300);
            if !inactive {
                tracing::info!("Removing inactive client: {}", id);
            }
            inactive
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);
    
    println!("SHARP-256 Relay Server");
    println!("======================\n");
    
    let server = RelayServer::new(args.bind).await?;
    server.run().await
}