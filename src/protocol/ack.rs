use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use crate::protocol::constants::PROTOCOL_VERSION;

/// Первичный ACK от отправителя к получателю
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAck {
    pub version: u8,
    pub file_name: String,
    pub file_size: u64,
    pub sender_ip: IpAddr,
    pub receiver_ip: IpAddr,
    pub packet_size: u32,
    pub batch_size: u16,
    pub use_encryption: bool,
}

impl InitialAck {
    pub fn new(
        file_name: String,
        file_size: u64,
        sender_ip: IpAddr,
        receiver_ip: IpAddr,
        batch_size: u16,
        use_encryption: bool,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            file_name,
            file_size,
            sender_ip,
            receiver_ip,
            packet_size: 256 * 1024, // SHARP-256
            batch_size,
            use_encryption,
        }
    }
}

/// Ответный ACK от получателя к отправителю
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAckResponse {
    pub accept_transfer: bool,
    pub reason: Option<String>, // Причина отказа, если accept_transfer = false
}

/// Информация о потерянных пакетах
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LostPacket {
    pub batch_number: u32,
    pub packet_number: u16,
}

impl LostPacket {
    pub fn new(batch_number: u32, packet_number: u16) -> Self {
        Self {
            batch_number,
            packet_number,
        }
    }
}

/// Параметры SAO (System of Automatic Optimization)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SaoParams {
    pub optimized_mode: bool,
    pub batch_size: u16,
    pub current_score: f64,
    pub avg_rtt_ms: f64,
    pub loss_rate: f64,
    pub bandwidth_utilization: f64,
}

impl Default for SaoParams {
    fn default() -> Self {
        Self {
            optimized_mode: false,
            batch_size: crate::protocol::constants::INITIAL_BATCH_SIZE,
            current_score: 0.5,
            avg_rtt_ms: 0.0,
            loss_rate: 0.0,
            bandwidth_utilization: 0.0,
        }
    }
}

/// Контрольный ACK для проверки целостности и перезапроса
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAck {
    pub batch_range_start: u32,
    pub batch_range_end: u32,
    pub lost_packets: Vec<LostPacket>, // Пустой вектор = все пакеты получены
    pub lost_hashes: Vec<u32>, // Номера партий с потерянными хешами
    pub sao_params: SaoParams,
    pub ping_ms: f64,
    pub timestamp: u64,
}

impl ControlAck {
    pub fn new(batch_start: u32, batch_end: u32, sao_params: SaoParams) -> Self {
        Self {
            batch_range_start: batch_start,
            batch_range_end: batch_end,
            lost_packets: Vec::new(),
            lost_hashes: Vec::new(),
            sao_params,
            ping_ms: 0.0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Проверка, что все пакеты получены успешно
    pub fn is_all_received(&self) -> bool {
        self.lost_packets.is_empty() && self.lost_hashes.is_empty()
    }

    /// Добавление потерянного пакета
    pub fn add_lost_packet(&mut self, batch_number: u32, packet_number: u16) {
        self.lost_packets.push(LostPacket::new(batch_number, packet_number));
    }

    /// Добавление партии с потерянными хешами
    pub fn add_lost_hash_batch(&mut self, batch_number: u32) {
        if !self.lost_hashes.contains(&batch_number) {
            self.lost_hashes.push(batch_number);
        }
    }
}

/// Финальный ACK завершения передачи
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalAck {
    pub transfer_complete: bool,
    pub total_bytes_received: u64,
    pub file_hash: String, // BLAKE3 хеш всего файла
    pub transfer_time_ms: u64,
    pub average_speed_mbps: f64,
}

/// ACK для возобновления передачи
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeAck {
    pub file_name: String,
    pub file_size: u64,
    pub last_batch_number: u32,
    pub last_packet_in_batch: u16,
    pub bytes_transferred: u64,
    pub partial_file_hash: String, // Хеш уже переданной части
    pub resume_token: String, // Уникальный токен для проверки
}

/// Ответ на запрос возобновления
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeAckResponse {
    pub can_resume: bool,
    pub resume_from_batch: u32,
    pub resume_from_packet: u16,
    pub reason: Option<String>, // Причина, если can_resume = false
}