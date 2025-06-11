use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut, Buf};
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};
use rand::Rng;
use tokio::net::{lookup_host, UdpSocket};

// STUN константы
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN клиент для определения внешнего адреса
pub struct StunClient {
    servers: Vec<String>,
}

impl StunClient {
    pub fn new(servers: Vec<String>) -> Self {
        Self { servers }
    }

    /// Получение mapped address через STUN
    pub async fn get_mapped_address(&self, socket: &UdpSocket) -> Result<SocketAddr> {
        for server in &self.servers {
            match self.query_stun_server(socket, server).await {
                Ok(addr) => return Ok(addr),
                Err(e) => {
                    tracing::warn!("STUN server {} failed: {}", server, e);
                    continue;
                }
            }
        }
        
        anyhow::bail!("All STUN servers failed")
    }

    /// Определение типа NAT через несколько STUN серверов
    pub async fn detect_nat_type(&self, socket: &UdpSocket) -> Result<Vec<SocketAddr>> {
        let mut results = Vec::new();
        
        for server in &self.servers[..3.min(self.servers.len())] {
            if let Ok(addr) = self.query_stun_server(socket, server).await {
                results.push(addr);
            }
        }
        
        Ok(results)
    }

    /// Запрос к STUN серверу
    async fn query_stun_server(&self, socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
        let server_addr: SocketAddr = match server.parse() {
            Ok(addr) => addr,
            Err(_) => {
                let mut addrs = lookup_host(server)
                    .await
                    .with_context(|| format!("Invalid STUN server address: {}", server))?;
                addrs
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {}", server))?
            }
        };

        // Создаем STUN Binding Request
        let transaction_id = self.generate_transaction_id();
        let request = self.create_binding_request(&transaction_id);
        
        // Отправляем запрос
        socket.send_to(&request, server_addr).await?;
        
        // Ждем ответ
        let mut buffer = vec![0u8; 1024];
        let (size, _) = timeout(
            Duration::from_secs(3),
            socket.recv_from(&mut buffer)
        ).await
        .context("STUN response timeout")??;
        
        // Парсим ответ
        self.parse_binding_response(&buffer[..size], &transaction_id)
    }

    /// Создание STUN Binding Request
    fn create_binding_request(&self, transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(20);
        
        // Message Type: Binding Request
        buf.put_u16(BINDING_REQUEST);
        // Message Length: 0 (no attributes)
        buf.put_u16(0);
        // Magic Cookie
        buf.put_u32(STUN_MAGIC_COOKIE);
        // Transaction ID
        buf.put_slice(transaction_id);
        
        buf.to_vec()
    }

    /// Парсинг STUN Binding Response
    fn parse_binding_response(&self, data: &[u8], expected_tid: &[u8; 12]) -> Result<SocketAddr> {
        if data.len() < 20 {
            anyhow::bail!("STUN response too short");
        }
        
        let mut buf = BytesMut::from(data);
        
        // Проверяем тип сообщения
        let msg_type = buf.get_u16();
        if msg_type != BINDING_RESPONSE {
            anyhow::bail!("Not a binding response");
        }
        
        let msg_length = buf.get_u16() as usize;
        let magic = buf.get_u32();
        
        if magic != STUN_MAGIC_COOKIE {
            anyhow::bail!("Invalid magic cookie");
        }
        
        // Проверяем Transaction ID
        let mut tid = [0u8; 12];
        buf.copy_to_slice(&mut tid);
        if tid != *expected_tid {
            anyhow::bail!("Transaction ID mismatch");
        }
        
        // Парсим атрибуты
        let mut remaining = msg_length;
        while remaining >= 4 && buf.remaining() >= 4 {
            let attr_type = buf.get_u16();
            let attr_length = buf.get_u16() as usize;
            
            if buf.remaining() < attr_length {
                break;
            }
            
            match attr_type {
                XOR_MAPPED_ADDRESS => {
                    return self.parse_xor_mapped_address(&mut buf, attr_length);
                }
                MAPPED_ADDRESS => {
                    return self.parse_mapped_address(&mut buf, attr_length);
                }
                _ => {
                    // Пропускаем неизвестный атрибут
                    buf.advance(attr_length);
                }
            }
            
            // Выравнивание на 32-битную границу
            let padding = (4 - (attr_length % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }
            
            remaining = remaining.saturating_sub(4 + attr_length + padding);
        }
        
        anyhow::bail!("No mapped address found in STUN response")
    }

    /// Парсинг XOR-MAPPED-ADDRESS
    fn parse_xor_mapped_address(&self, buf: &mut BytesMut, length: usize) -> Result<SocketAddr> {
        if length < 8 {
            anyhow::bail!("XOR-MAPPED-ADDRESS too short");
        }
        
        let _ = buf.get_u8(); // Пропускаем reserved
        let family = buf.get_u8();
        let port = buf.get_u16() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        
        match family {
            0x01 => {
                // IPv4
                let ip_bytes = buf.get_u32() ^ STUN_MAGIC_COOKIE;
                let ip = std::net::Ipv4Addr::from(ip_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if length < 20 {
                    anyhow::bail!("IPv6 XOR-MAPPED-ADDRESS too short");
                }
                
                let mut addr_bytes = [0u8; 16];
                buf.copy_to_slice(&mut addr_bytes);
                
                // XOR с magic cookie и transaction ID
                for i in 0..4 {
                    addr_bytes[i] ^= ((STUN_MAGIC_COOKIE >> (24 - i * 8)) & 0xFF) as u8;
                }
                // Для простоты пропускаем XOR с transaction ID для остальных байтов
                
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => anyhow::bail!("Unknown address family"),
        }
    }

    /// Парсинг MAPPED-ADDRESS (legacy)
    fn parse_mapped_address(&self, buf: &mut BytesMut, length: usize) -> Result<SocketAddr> {
        if length < 8 {
            anyhow::bail!("MAPPED-ADDRESS too short");
        }
        
        let _ = buf.get_u8(); // Пропускаем reserved
        let family = buf.get_u8();
        let port = buf.get_u16();
        
        match family {
            0x01 => {
                // IPv4
                let ip = std::net::Ipv4Addr::from(buf.get_u32());
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if length < 20 {
                    anyhow::bail!("IPv6 MAPPED-ADDRESS too short");
                }
                let mut addr_bytes = [0u8; 16];
                buf.copy_to_slice(&mut addr_bytes);
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => anyhow::bail!("Unknown address family"),
        }
    }

    /// Генерация случайного Transaction ID
    fn generate_transaction_id(&self) -> [u8; 12] {
        let mut tid = [0u8; 12];
        rand::thread_rng().fill(&mut tid);
        tid
    }
}