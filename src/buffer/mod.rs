use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use crate::protocol::packet::Packet;
use crate::protocol::constants::*;

/// Буфер для хранения последних отправленных пакетов
pub struct PacketBuffer {
    packets: Arc<RwLock<VecDeque<(u32, u16, Packet)>>>, // (batch_number, packet_in_batch, packet)
    hashes: Arc<RwLock<HashMap<u32, Vec<blake3::Hash>>>>, // batch_number -> hashes
    max_packets: usize,
}

impl PacketBuffer {
    pub fn new() -> Self {
        Self {
            packets: Arc::new(RwLock::new(VecDeque::with_capacity(PACKET_BUFFER_SIZE))),
            hashes: Arc::new(RwLock::new(HashMap::new())),
            max_packets: PACKET_BUFFER_SIZE,
        }
    }

    /// Добавление пакета в буфер
    pub fn add_packet(&self, batch_number: u32, packet_in_batch: u16, packet: Packet) {
        let mut packets = self.packets.write();
        
        // Удаляем старые пакеты, если буфер переполнен
        while packets.len() >= self.max_packets {
            if let Some((old_batch, _, _)) = packets.pop_front() {
                // Удаляем хеши старой партии, если все её пакеты удалены
                let has_more = packets.iter().any(|(b, _, _)| *b == old_batch);
                if !has_more {
                    self.hashes.write().remove(&old_batch);
                }
            }
        }
        
        packets.push_back((batch_number, packet_in_batch, packet));
    }

    /// Добавление хешей партии
    pub fn add_batch_hashes(&self, batch_number: u32, hashes: Vec<blake3::Hash>) {
        self.hashes.write().insert(batch_number, hashes);
    }

    /// Получение пакета для перезапроса
    pub fn get_packet(&self, batch_number: u32, packet_in_batch: u16) -> Option<Packet> {
        self.packets.read()
            .iter()
            .find(|(b, p, _)| *b == batch_number && *p == packet_in_batch)
            .map(|(_, _, packet)| packet.clone())
    }

    /// Получение хешей партии
    pub fn get_batch_hashes(&self, batch_number: u32) -> Option<Vec<blake3::Hash>> {
        self.hashes.read().get(&batch_number).cloned()
    }

    /// Очистка буферов после успешного подтверждения
    pub fn clear_before_batch(&self, confirmed_batch: u32) {
        let mut packets = self.packets.write();
        let mut hashes = self.hashes.write();
        
        // Удаляем все пакеты до подтвержденной партии
        packets.retain(|(batch, _, _)| *batch > confirmed_batch);
        
        // Удаляем хеши старых партий
        hashes.retain(|batch, _| *batch > confirmed_batch);
    }

    /// Полная очистка буферов
    pub fn clear(&self) {
        self.packets.write().clear();
        self.hashes.write().clear();
    }
}

/// Буфер для приема пакетов с обработкой out-of-order доставки
pub struct ReceiveBuffer {
    active_batches: Arc<RwLock<HashMap<u32, BatchBuffer>>>,
    batch_timeout_ms: u64,
}

#[derive(Debug)]
struct BatchBuffer {
    packets: HashMap<u16, Packet>,
    expected_count: u16,
    received_hashes: Option<Vec<blake3::Hash>>,
    created_at: Instant,
    completed: bool,
}

impl ReceiveBuffer {
    pub fn new() -> Self {
        Self {
            active_batches: Arc::new(RwLock::new(HashMap::new())),
            batch_timeout_ms: INCOMPLETE_BATCH_TIMEOUT_MS,
        }
    }

    /// Добавление пакета данных
    pub fn add_data_packet(&self, packet: Packet) -> Result<bool, String> {
        let mut batches = self.active_batches.write();
        
        let batch_buffer = batches.entry(packet.header.batch_number)
            .or_insert_with(|| BatchBuffer {
                packets: HashMap::new(),
                expected_count: packet.header.total_packets,
                received_hashes: None,
                created_at: Instant::now(),
                completed: false,
            });

        // Проверяем, не истек ли таймаут
        if batch_buffer.created_at.elapsed().as_millis() > self.batch_timeout_ms as u128 {
            return Err("Batch timeout exceeded".to_string());
        }

        // Добавляем пакет
        batch_buffer.packets.insert(packet.header.packet_in_batch, packet);

        // Проверяем, получили ли мы все пакеты партии
        let is_complete = batch_buffer.packets.len() == batch_buffer.expected_count as usize
            && batch_buffer.packets.contains_key(&(batch_buffer.expected_count - 1))
            && batch_buffer.packets[&(batch_buffer.expected_count - 1)].header.is_last_in_batch();

        if is_complete {
            batch_buffer.completed = true;
        }

        Ok(is_complete)
    }

    /// Добавление хешей партии
    pub fn add_batch_hashes(&self, batch_number: u32, hashes: Vec<blake3::Hash>) -> Result<(), String> {
        let mut batches = self.active_batches.write();
        
        match batches.get_mut(&batch_number) {
            Some(batch_buffer) => {
                batch_buffer.received_hashes = Some(hashes);
                Ok(())
            }
            None => {
                // Создаем буфер для партии, если его еще нет
                let batch_buffer = BatchBuffer {
                    packets: HashMap::new(),
                    expected_count: 0,
                    received_hashes: Some(hashes),
                    created_at: Instant::now(),
                    completed: false,
                };
                batches.insert(batch_number, batch_buffer);
                Ok(())
            }
        }
    }

    /// Получение завершенной партии для проверки
    pub fn get_completed_batch(&self, batch_number: u32) -> Option<(Vec<Packet>, Vec<blake3::Hash>)> {
        let batches = self.active_batches.read();
        
        if let Some(batch_buffer) = batches.get(&batch_number) {
            if batch_buffer.completed && batch_buffer.received_hashes.is_some() {
                // Сортируем пакеты по порядку
                let mut packets: Vec<_> = batch_buffer.packets.values().cloned().collect();
                packets.sort_by_key(|p| p.header.packet_in_batch);
                
                return Some((packets, batch_buffer.received_hashes.clone().unwrap()));
            }
        }
        
        None
    }

    /// Удаление обработанной партии
    pub fn remove_batch(&self, batch_number: u32) {
        self.active_batches.write().remove(&batch_number);
    }

    /// Очистка устаревших партий
    pub fn cleanup_expired(&self) {
        let mut batches = self.active_batches.write();
        let now = Instant::now();
        
        batches.retain(|_, batch| {
            now.duration_since(batch.created_at).as_millis() <= self.batch_timeout_ms as u128
        });
    }

    /// Получение списка незавершенных партий
    pub fn get_incomplete_batches(&self) -> Vec<(u32, Vec<u16>)> {
        let batches = self.active_batches.read();
        let mut result = Vec::new();
        
        for (&batch_num, batch_buffer) in batches.iter() {
            if !batch_buffer.completed {
                let missing: Vec<u16> = (0..batch_buffer.expected_count)
                    .filter(|i| !batch_buffer.packets.contains_key(i))
                    .collect();
                
                if !missing.is_empty() {
                    result.push((batch_num, missing));
                }
            }
        }
        
        result
    }
}