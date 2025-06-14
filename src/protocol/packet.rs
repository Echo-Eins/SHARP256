use bytes::{Buf, BufMut, BytesMut};
use std::io::{self, Error, ErrorKind};
use crate::protocol::constants::*;

/// Заголовок пакета SHARP-256 (30 байт)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub magic_number: u16,          // 2 bytes - идентификатор протокола
    pub version: u8,                // 1 byte - версия протокола
    pub packet_type: PacketType,    // 1 byte - тип пакета
    pub batch_number: u32,          // 4 bytes - номер партии
    pub packet_in_batch: u16,       // 2 bytes - номер пакета в партии
    pub total_packets: u16,         // 2 bytes - всего пакетов в партии
    pub payload_length: u32,        // 4 bytes - размер полезной нагрузки
    pub flags: u8,                  // 1 byte - флаги
    pub sequence: u32,              // 4 bytes - глобальный номер (для отладки)
    pub reserved: [u8; 9],          // 9 bytes - резерв
}

impl PacketHeader {
    pub fn new(packet_type: PacketType) -> Self {
        Self {
            magic_number: MAGIC_NUMBER,
            version: PROTOCOL_VERSION,
            packet_type,
            batch_number: 0,
            packet_in_batch: 0,
            total_packets: 0,
            payload_length: 0,
            flags: 0,
            sequence: 0,
            reserved: [0; 9],
        }
    }

    /// Сериализация заголовка в байты
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(SHARP_HEADER_SIZE);
        
        buf.put_u16(self.magic_number);
        buf.put_u8(self.version);
        buf.put_u8(self.packet_type as u8);
        buf.put_u32(self.batch_number);
        buf.put_u16(self.packet_in_batch);
        buf.put_u16(self.total_packets);
        buf.put_u32(self.payload_length);
        buf.put_u8(self.flags);
        buf.put_u32(self.sequence);
        buf.put_slice(&self.reserved);
        
        buf
    }

    /// Десериализация заголовка из байтов
    pub fn from_bytes(buf: &mut BytesMut) -> io::Result<Self> {
        if buf.len() < SHARP_HEADER_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Buffer too small for packet header"
            ));
        }

        let magic_number = buf.get_u16();
        if magic_number != MAGIC_NUMBER {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid magic number"
            ));
        }

        let version = buf.get_u8();
        if version != PROTOCOL_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Unsupported protocol version"
            ));
        }

        let packet_type = match buf.get_u8() {
            0x01 => PacketType::Data,
            0x02 => PacketType::Hash,
            0x03 => PacketType::Ack,
            0x04 => PacketType::Control,
            0x05 => PacketType::Resume,
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid packet type")),
        };

        let batch_number = buf.get_u32();
        let packet_in_batch = buf.get_u16();
        let total_packets = buf.get_u16();
        let payload_length = buf.get_u32();
        let flags = buf.get_u8();
        let sequence = buf.get_u32();
        
        let mut reserved = [0u8; 9];
        buf.copy_to_slice(&mut reserved);

        Ok(Self {
            magic_number,
            version,
            packet_type,
            batch_number,
            packet_in_batch,
            total_packets,
            payload_length,
            flags,
            sequence,
            reserved,
        })
    }

    /// Проверка, является ли пакет последним в партии
    pub fn is_last_in_batch(&self) -> bool {
        self.flags & packet_flags::LAST_IN_BATCH != 0
    }

    /// Установка флага последнего пакета в партии
    pub fn set_last_in_batch(&mut self) {
        self.flags |= packet_flags::LAST_IN_BATCH;
    }

    /// Рассчет позиции данных в файле
    pub fn calculate_file_offset(&self, batch_size: u16) -> u64 {
        // ИСПРАВЛЕНО: учитывать фактический размер пакетов
        let block_size = if self.payload_length < BLOCK_SIZE as u32 {
            self.payload_length as u64
        } else {
            BLOCK_SIZE as u64
        };

        let packets_before = self.batch_number as u64 * batch_size as u64 + self.packet_in_batch as u64;
        packets_before * block_size
    }
}

/// Полный пакет с заголовком и данными
#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(header: PacketHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Сериализация пакета в байты для отправки
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = self.header.to_bytes();
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Десериализация пакета из байтов
    pub fn from_bytes(buf: &mut BytesMut) -> io::Result<Self> {
        let header = PacketHeader::from_bytes(buf)?;
        
        if buf.len() < header.payload_length as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Buffer too small for payload"
            ));
        }

        let payload = buf.split_to(header.payload_length as usize).to_vec();

        if !buf.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Trailing data after packet"
            ));
        }
        
        Ok(Self { header, payload })
    }
}