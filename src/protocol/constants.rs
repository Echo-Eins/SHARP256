/// Константы протокола SHARP-256

// Основные параметры протокола
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAGIC_NUMBER: u16 = 0x5348; // "SH" в hex

// Размеры данных
pub const BLOCK_SIZE: usize = 256 * 1024; // 256 KB
pub const MAX_PACKET_SIZE: usize = 64 * 1024; // 64 KB для GSO/GRO
pub const MTU_SIZE: usize = 1500;
pub const UDP_HEADER_SIZE: usize = 8;
pub const SHARP_HEADER_SIZE: usize = 30;
pub const MAX_PAYLOAD_SIZE_MTU: usize = MTU_SIZE - UDP_HEADER_SIZE - SHARP_HEADER_SIZE; // ~1462 bytes
pub const MAX_PAYLOAD_SIZE_GSO: usize = MAX_PACKET_SIZE - SHARP_HEADER_SIZE; // ~65506 bytes

// Параметры партий (batch)
pub const MIN_BATCH_SIZE: u16 = 5;
pub const INITIAL_BATCH_SIZE: u16 = 10;
pub const MAX_BATCH_SIZE: u16 = 50;
pub const BATCHES_BEFORE_ACK: u32 = 10;
pub const SAO_RECALC_INTERVAL: u32 = 100; // Пересчет SAO каждые 100 партий

// Размер буферов
pub const PACKET_BUFFER_SIZE: usize = 100; // Последние 100 пакетов
pub const BATCH_BUFFER_SIZE: usize = 10; // 10 партий

// Таймауты
pub const ACK_TIMEOUT_MS: u64 = 120_000; // 2 минуты
pub const HASH_RETRY_INTERVAL_MS: u64 = 10_000; // 10 секунд
pub const INCOMPLETE_BATCH_TIMEOUT_MS: u64 = 30_000; // 30 секунд

// Типы пакетов
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 0x01,
    Hash = 0x02,
    Ack = 0x03,
    Control = 0x04,
    Resume = 0x05
}

// Флаги пакетов
pub mod packet_flags {
    pub const LAST_IN_BATCH: u8 = 0x01;
    pub const START_TRANSFER: u8 = 0x02;
    pub const END_TRANSFER: u8 = 0x04;
    pub const RETRANSMIT: u8 = 0x08;
    pub const ENCRYPTED: u8 = 0x10;
}

// SAO параметры
pub const SAO_SCORE_INCREASE_THRESHOLD: f64 = 0.8;
pub const SAO_SCORE_DECREASE_THRESHOLD: f64 = 0.4;
pub const SAO_BATCH_SIZE_STEP: u16 = 5;