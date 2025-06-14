
use bytes::{BufMut, BytesMut, Buf};
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};
use rand::Rng;
use tokio::net::{lookup_host, UdpSocket};
use rand::{rngs::OsRng, RngCore};
use crc32fast::Hasher as Crc32Hasher;
use std::net::{SocketAddrV6};
use anyhow::Context;
use super::NatResult as Result;

use crc32fast::Hasher;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// STUN константы
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

const USERNAME: u16 = 0x0006;

const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
const FINGERPRINT_ATTR: u16 = 0x8028;

/// STUN клиент для определения внешнего адреса
pub struct StunClient {
    servers: Vec<String>,
    credentials: Option<(String, String)>,
}

impl StunClient {
    pub fn new(servers: Vec<String>) -> Self {
        Self { servers, password: None }
    }

    /// Создание клиента с паролем для проверки целостности
    pub fn with_password(servers: Vec<String>, password: String) -> Self {
        Self { servers, password: Some(password) }
    }

    /// Получение mapped address через STUN
    pub async fn get_mapped_address(&self, socket: &UdpSocket) -> Result<SocketAddr> {

        let zone = match socket.local_addr()? {
            SocketAddr::V6(v6) => v6.scope_id(),
            _ => 0,
        };

        let servers: Vec<_> = self.servers.iter().take(3).collect();

        for attempt in 0..3 {
            let mut tids = Vec::new();

            // Отправляем запросы ко всем серверам
            for server in &servers {
                if let Ok(addr) = self.resolve_server(server).await {
                    let tid = self.generate_transaction_id();
                    let req = self.create_binding_request(&tid);
                    if socket.send_to(&req, addr).await.is_ok() {
                        tids.push(tid);
                    }
                }
            }
            let mut buf = vec![0u8; 1024];
            if let Ok(Ok((size, _))) =
                timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await
            {
                for tid in tids {
                    if let Ok(addr) = self.parse_binding_response(&buf[..size], &tid, zone) {
                        return Ok(addr);
                    }
                }
            }
            tracing::debug!("STUN attempt {} failed", attempt + 1);
        }

        /// Определение типа NAT через несколько STUN серверов
        pub async fn detect_nat_type(&self, socket: &UdpSocket) -> Result<Vec<(SocketAddr, bool)>> {
            let mut results = Vec::new();

            let servers: Vec<_> = self.servers.iter().take(3).collect();

            for (idx, server) in servers.iter().enumerate() {
                if let Ok(addr) = self.query_stun_server(socket, server).await {
                    if idx == 0 {
                        results.push((addr, false));
                    } else {
                        let changed = results
                            .first()
                            .map(|(first, _)| first.ip() != addr.ip() || first.port() != addr.port())
                            .unwrap_or(false);
                        results.push((addr, changed));
                    }
                }
            }

            Ok(results)
        }

        /// Запрос к STUN серверу
        async fn query_stun_server(&self, socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
            let server_addr = self.resolve_server(server).await?;

            let transaction_id = self.generate_transaction_id();
            let request = self.create_binding_request(&transaction_id);

            let mut rto = Duration::from_millis(500);
            let mut buf = vec![0u8; 1024];

            for _ in 0..7 {
                socket.send_to(&request, server_addr).await?;

                let jitter: i64 = rand::thread_rng().gen_range(-50..=50);
                let wait = if jitter >= 0 {
                    rto + Duration::from_millis(jitter as u64)
                } else {
                    rto.saturating_sub(Duration::from_millis((-jitter) as u64))
                };

                if let Ok(Ok((size, addr))) = timeout(wait, socket.recv_from(&mut buf)).await {
                    if addr == server_addr {
                        return self.parse_binding_response(&buf[..size], &transaction_id);
                    }
                }

                rto = std::cmp::min(rto * 2, Duration::from_millis(3200));
            }

            anyhow::bail!("STUN server {} did not respond", server)
        }

        async fn resolve_server(&self, server: &str) -> Result<SocketAddr> {
            match server.parse() {
                Ok(addr) => Ok(addr),
                Err(_) => {
                    let mut addrs = lookup_host(server)
                        .await
                        .with_context(|| format!("Invalid STUN server address: {}", server))?;
                    addrs
                        .next()
                        .ok_or_else(|| super::NatError::transient(format!("DNS lookup failed for {}", server)))
                }
            }
        }

        /// Создание STUN Binding Request
        fn create_binding_request(&self, transaction_id: &[u8; 12]) -> Vec<u8> {
            let use_integrity = self.password.is_some();
            let len_without_fp = if use_integrity { 36 } else { 0 };
            let total_len = len_without_fp + 8;

            let mut buf = BytesMut::with_capacity(20 + total_len);

            // Header
            buf.put_u16(BINDING_REQUEST);
            buf.put_u16(len_without_fp as u16);
            buf.put_u32(STUN_MAGIC_COOKIE);
            buf.put_slice(transaction_id);

            if let Some(pwd) = &self.password {
                buf.put_u16(MESSAGE_INTEGRITY_SHA256);
                buf.put_u16(32);
                let pos = buf.len();
                buf.resize(buf.len() + 32, 0);

                let mut mac: Hmac<Sha256> = Hmac::new_from_slice(pwd.as_bytes()).unwrap();
                mac.update(&buf);
                let res = mac.finalize().into_bytes();
                buf[pos..pos + 32].copy_from_slice(&res);
            }

            let fp_offset = buf.len();
            buf.put_u16(FINGERPRINT_ATTR);
            buf.put_u16(4);
            buf.put_u32(0);

            let len_bytes = (total_len as u16).to_be_bytes();
            buf[2] = len_bytes[0];
            buf[3] = len_bytes[1];

            let crc = {
                let mut hasher = Hasher::new();
                hasher.update(&buf[..fp_offset + 4]);
                hasher.finalize() ^ 0x5354554e
            };
            buf[fp_offset + 4..fp_offset + 8].copy_from_slice(&crc.to_be_bytes());

            buf.to_vec()
        }

        /// Парсинг STUN Binding Response
        fn parse_binding_response(
            &self,
            data: &[u8],
            expected_tid: &[u8; 12],
            zone: u32,
        ) -> Result<SocketAddr> {
            if data.len() < 20 {
                return Err(super::NatError::transient("STUN response too short"));
            }

            let total_len = 20 + (u16::from_be_bytes([data[2], data[3]]) as usize);
            if data.len() < total_len {
                return Err(super::NatError::transient("Not a binding response"));
            }

            let mut buf = BytesMut::from(&data[..total_len]);

            // Проверяем тип сообщения
            let msg_type = buf.get_u16();
            if msg_type != BINDING_RESPONSE {
                return Err(super::NatError::transient("STUN message length invalid"));
            }

            let _msg_length = buf.get_u16() as usize;
            let magic = buf.get_u32();
        }

        if magic != STUN_MAGIC_COOKIE {
            return Err(super::NatError::transient("Invalid magic cookie"));
        }

        // Проверяем Transaction ID
        let mut tid = [0u8; 12];
        buf.copy_to_slice(&mut tid);
        if tid != *expected_tid {
            return Err(super::NatError::transient("Transaction ID mismatch"));
        }

        let mut offset = 20usize;
        let mut mapped: Option<SocketAddr> = None;
        let mut mi_offset: Option<(usize, usize)> = None;
        let mut fp_offset: Option<usize> = None;

        while offset + 4 <= total_len {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let val_start = offset + 4;
            let val_end = val_start + attr_length;
            if val_end > total_len {
                break;
            }

            match attr_type {
                XOR_MAPPED_ADDRESS => {
                    let mut tmp = BytesMut::from(&data[val_start..val_end]);
                    mapped = Some(self.parse_xor_mapped_address(&mut tmp, attr_length, &tid)?);
                }
                MAPPED_ADDRESS => {
                    let mut tmp = BytesMut::from(&data[val_start..val_end]);
                    mapped = Some(self.parse_mapped_address(&mut tmp, attr_length)?);
                }
                MESSAGE_INTEGRITY_SHA256 => {
                    mi_offset = Some((offset, attr_length));
                }
                _ => {
                    // Пропускаем неизвестный атрибут
                    FINGERPRINT_ATTR => {
                        fp_offset = Some(offset);
                    }
                    _ => {}
                }
            }

            // Выравнивание на 32-битную границу
            offset = val_end;
            let padding = (4 - (attr_length % 4)) % 4;
            offset += padding;
        }

        if let Some(fp) = fp_offset {
            if fp + 8 > total_len {
                anyhow::bail!("FINGERPRINT attribute truncated");
            }
            let expected_crc = {
                let mut hasher = Hasher::new();
                hasher.update(&data[..fp + 4]);
                hasher.finalize() ^ 0x5354554e
            };
            let recv_crc = u32::from_be_bytes(data[fp + 4..fp + 8].try_into().unwrap());
            if expected_crc != recv_crc {
                anyhow::bail!("FINGERPRINT check failed");
            }
        }
        if let Some((mi_pos, mi_len)) = mi_offset {
            if let Some(ref pwd) = self.password {
                if mi_pos + 4 + mi_len > total_len {
                    anyhow::bail!("MESSAGE-INTEGRITY attribute truncated");
                }

                let mi_end = mi_pos + 4 + mi_len;
                let mut tmp = Vec::from(&data[..mi_end]);
                let len_bytes = ((mi_end - 20) as u16).to_be_bytes();
                tmp[2] = len_bytes[0];
                tmp[3] = len_bytes[1];
                for b in &mut tmp[mi_pos + 4..mi_end] {
                    *b = 0;
                }

                let mut mac: Hmac<Sha256> = Hmac::new_from_slice(pwd.as_bytes()).unwrap();
                mac.update(&tmp);
                let expected = mac.finalize().into_bytes();

                if expected[..mi_len] != data[mi_pos + 4..mi_end] {
                    anyhow::bail!("MESSAGE-INTEGRITY check failed");
                }
            }
        }

        mapped.ok_or_else(|| anyhow::anyhow!("No mapped address found in STUN response"))
    }

    /// Парсинг XOR-MAPPED-ADDRESS
    fn parse_xor_mapped_address(&self, buf: &mut BytesMut, length: usize, transaction_id: &[u8; 12]) -> Result<SocketAddr> {
        if length < 8 {
            return Err(super::NatError::transient("XOR-MAPPED-ADDRESS too short"));
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
                    return Err(super::NatError::transient("IPv6 XOR-MAPPED-ADDRESS too short"));
                }
                
                let mut addr_bytes = [0u8; 16];
                buf.copy_to_slice(&mut addr_bytes);

                // XOR all 16 bytes with magic cookie and transaction ID
                // RFC 5389: first 4 bytes are XORed with the magic cookie,
                // the remaining 12 bytes are XORed with the transaction ID

                for i in 0..4 {
                    addr_bytes[i] ^= ((STUN_MAGIC_COOKIE >> (8 * (3 - i))) & 0xFF) as u8;
                }
                for i in 0..12 {
                    addr_bytes[i + 4] ^= transaction_id[i];
                }
                
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, zone)))
            }
            _ => return Err(super::NatError::transient("Unknown address family")),
        }
    }

    /// Генерация случайного Transaction ID
    fn generate_transaction_id(&self) -> [u8; 12] {
        let mut tid = [0u8; 12];
        OsRng.fill_bytes(&mut tid);
        tid
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr};
    use bytes::BytesMut;

    #[test]
    fn parse_ipv6_xor_mapped_address() {
        let client = StunClient::new(vec![]);

        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let port: u16 = 54321;

        // Create XOR-MAPPED-ADDRESS attribute value
        let mut attr_value = BytesMut::with_capacity(20);
        attr_value.put_u8(0); // reserved
        attr_value.put_u8(0x02); // family
        attr_value.put_u16(port ^ ((STUN_MAGIC_COOKIE >> 16) as u16));
        let ip_bytes = ip.octets();
        let mut xored_ip = [0u8; 16];
        for i in 0..4 {
            xored_ip[i] = ip_bytes[i] ^ ((STUN_MAGIC_COOKIE >> (8 * (3 - i))) & 0xFF) as u8;
        }
        for i in 0..12 {
            xored_ip[i + 4] = ip_bytes[i + 4] ^ transaction_id[i];
        }
        attr_value.extend_from_slice(&xored_ip);

        // Build STUN message
        let msg_len = 4 + attr_value.len();
        let mut msg = BytesMut::with_capacity(20 + msg_len);
        msg.put_u16(BINDING_RESPONSE);
        msg.put_u16(msg_len as u16);
        msg.put_u32(STUN_MAGIC_COOKIE);
        msg.put_slice(&transaction_id);
        msg.put_u16(XOR_MAPPED_ADDRESS);
        msg.put_u16(attr_value.len() as u16);
        msg.put_slice(&attr_value);

        let result = client
            .parse_binding_response(&msg, &transaction_id, 0)
            .unwrap();
        assert_eq!(result, SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));
    }

    #[test]
    fn create_request_with_integrity() {
        let client = StunClient::with_credentials(vec![], "user".into(), "pass".into());
        let tid = [0u8; 12];
        let msg = client.create_binding_request(&tid);

        let len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(len + 20, msg.len());

        // Fingerprint attribute type should appear last
        let attr_type = u16::from_be_bytes([msg[msg.len()-8], msg[msg.len()-7]]);
        assert_eq!(attr_type, FINGERPRINT);
    }

    #[test]
    fn transaction_id_unique() {
        let client = StunClient::new(vec![]);
        let tid1 = client.generate_transaction_id();
        let tid2 = client.generate_transaction_id();
        assert_eq!(tid1.len(), 12);
        assert_eq!(tid2.len(), 12);
        assert_ne!(tid1, tid2);
    }
}