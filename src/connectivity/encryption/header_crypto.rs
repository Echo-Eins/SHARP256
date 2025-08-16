// src/connectivity/encryption/header_crypto.rs
//! Раздельное шифрование SHARP заголовков для обхода блокировок

#[cfg(feature = "relay-encryption")]
use anyhow::Result;
#[cfg(feature = "relay-encryption")]
use async_trait::async_trait;
#[cfg(feature = "relay-encryption")]
use bytes::BytesMut;
#[cfg(feature = "relay-encryption")]
use parking_lot::RwLock;
#[cfg(feature = "relay-encryption")]
use std::sync::Arc;
#[cfg(feature = "relay-encryption")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "relay-encryption")]
use tracing::{debug, trace, warn, error};

#[cfg(feature = "relay-encryption")]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};

#[cfg(feature = "relay-encryption")]
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit as AesKeyInit, Aead as AesAead,
    Nonce as AesNonce
};

#[cfg(feature = "relay-encryption")]
use super::{
    EncryptionAlgorithm, EncryptionConfig, EncryptionResult, EncryptionMetadata, Encryptor
};
#[cfg(feature = "relay-encryption")]
use crate::connectivity::config::HeaderEncryptionAlgorithm;
#[cfg(feature = "relay-encryption")]
use crate::protocol::{packet::PacketHeader, constants::SHARP_HEADER_SIZE};

/// Главный класс для шифрования SHARP заголовков
#[cfg(feature = "relay-encryption")]
#[derive(Debug, Clone)]
pub struct HeaderCrypto {
    /// Алгоритм шифрования
    algorithm: EncryptionAlgorithm,
    /// Ключ шифрования
    key: Arc<RwLock<[u8; 32]>>,
    /// Версия ключа для ротации
    key_version: Arc<RwLock<u32>>,
    /// Время последней ротации ключа
    last_key_rotation: Arc<RwLock<Option<Instant>>>,
    /// Интервал ротации ключа
    key_rotation_interval: Option<Duration>,
    /// Статистика шифрования
    stats: Arc<RwLock<EncryptionStats>>,
}

#[cfg(feature = "relay-encryption")]
#[derive(Debug, Default, Clone)]
struct EncryptionStats {
    /// Количество зашифрованных заголовков
    headers_encrypted: u64,
    /// Количество дешифрованных заголовков
    headers_decrypted: u64,
    /// Количество ошибок шифрования
    encryption_errors: u64,
    /// Количество ошибок дешифрования
    decryption_errors: u64,
    /// Общее время шифрования
    total_encrypt_time: Duration,
    /// Общее время дешифрования
    total_decrypt_time: Duration,
    /// Количество ротаций ключей
    key_rotations: u64,
}

#[cfg(feature = "relay-encryption")]
impl EncryptionStats {
    fn record_encryption(&mut self, duration: Duration) {
        self.headers_encrypted += 1;
        self.total_encrypt_time += duration;
    }

    fn record_decryption(&mut self, duration: Duration) {
        self.headers_decrypted += 1;
        self.total_decrypt_time += duration;
    }

    fn record_encryption_error(&mut self) {
        self.encryption_errors += 1;
    }

    fn record_decryption_error(&mut self) {
        self.decryption_errors += 1;
    }

    fn record_key_rotation(&mut self) {
        self.key_rotations += 1;
    }

    fn average_encrypt_time(&self) -> Duration {
        if self.headers_encrypted > 0 {
            self.total_encrypt_time / self.headers_encrypted as u32
        } else {
            Duration::ZERO
        }
    }

    fn average_decrypt_time(&self) -> Duration {
        if self.headers_decrypted > 0 {
            self.total_decrypt_time / self.headers_decrypted as u32
        } else {
            Duration::ZERO
        }
    }
}

#[cfg(feature = "relay-encryption")]
impl HeaderCrypto {
    /// Создание нового HeaderCrypto
    pub fn new(key: [u8; 32], algorithm: HeaderEncryptionAlgorithm) -> Result<Self> {
        // Проверяем силу ключа
        if !super::utils::validate_key_strength(&key) {
            return Err(anyhow::anyhow!("Weak encryption key provided"));
        }

        let encryption_algorithm = EncryptionAlgorithm::from(algorithm);

        debug!("Creating HeaderCrypto with algorithm: {:?}", encryption_algorithm);

        Ok(Self {
            algorithm: encryption_algorithm,
            key: Arc::new(RwLock::new(key)),
            key_version: Arc::new(RwLock::new(1)),
            last_key_rotation: Arc::new(RwLock::new(Some(Instant::now()))),
            key_rotation_interval: Some(Duration::from_secs(3600)), // 1 час
            stats: Arc::new(RwLock::new(EncryptionStats::default())),
        })
    }

    /// Создание с кастомной конфигурацией
    pub fn with_config(config: EncryptionConfig) -> Result<Self> {
        let mut crypto = Self::new(config.key, config.algorithm.into())?;
        crypto.key_rotation_interval = config.key_rotation_interval;
        Ok(crypto)
    }

    /// Шифрование SHARP заголовка
    pub fn encrypt_header(&self, header: &PacketHeader) -> Result<Vec<u8>> {
        let start_time = Instant::now();

        // Проверяем нужна ли ротация ключа
        if let Err(e) = self.check_key_rotation() {
            warn!("Key rotation check failed: {}", e);
        }

        let header_bytes = header.to_bytes();

        if header_bytes.len() != SHARP_HEADER_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid header size: expected {}, got {}",
                SHARP_HEADER_SIZE,
                header_bytes.len()
            ));
        }

        let result = self.encrypt_header_bytes(&header_bytes);

        match &result {
            Ok(_) => {
                self.stats.write().record_encryption(start_time.elapsed());
                trace!("Header encrypted successfully in {:?}", start_time.elapsed());
            }
            Err(_) => {
                self.stats.write().record_encryption_error();
                error!("Header encryption failed");
            }
        }

        result
    }

    /// Шифрование произвольных байтов заголовка
    pub fn encrypt_header_bytes(&self, header_bytes: &[u8]) -> Result<Vec<u8>> {
        let key = *self.key.read();
        let key_version = *self.key_version.read();

        match self.algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.encrypt_with_chacha20(&key, header_bytes, key_version)
            }
            EncryptionAlgorithm::AesGcm256 => {
                self.encrypt_with_aes256(&key, header_bytes, key_version)
            }
            EncryptionAlgorithm::AesGcm128 => {
                self.encrypt_with_aes128(&key, header_bytes, key_version)
            }
        }
    }

    /// Дешифрование заголовка
    pub fn decrypt_header(&self, encrypted_data: &[u8]) -> Result<PacketHeader> {
        let start_time = Instant::now();

        let decrypted_bytes = self.decrypt_header_bytes(encrypted_data);

        match &decrypted_bytes {
            Ok(_) => {
                self.stats.write().record_decryption(start_time.elapsed());
                trace!("Header decrypted successfully in {:?}", start_time.elapsed());
            }
            Err(_) => {
                self.stats.write().record_decryption_error();
                error!("Header decryption failed");
            }
        }

        let decrypted_bytes = decrypted_bytes?;

        if decrypted_bytes.len() != SHARP_HEADER_SIZE {
            return Err(anyhow::anyhow!(
                "Decrypted header has invalid size: expected {}, got {}",
                SHARP_HEADER_SIZE,
                decrypted_bytes.len()
            ));
        }

        // Парсим заголовок
        let mut buf = BytesMut::from(decrypted_bytes.as_slice());
        PacketHeader::from_bytes(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to parse decrypted header: {}", e))
    }

    /// Дешифрование произвольных байтов
    pub fn decrypt_header_bytes(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let key = *self.key.read();

        match self.algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.decrypt_with_chacha20(&key, encrypted_data)
            }
            EncryptionAlgorithm::AesGcm256 => {
                self.decrypt_with_aes256(&key, encrypted_data)
            }
            EncryptionAlgorithm::AesGcm128 => {
                self.decrypt_with_aes128(&key, encrypted_data)
            }
        }
    }

    /// Шифрование с ChaCha20-Poly1305
    fn encrypt_with_chacha20(&self, key: &[u8; 32], data: &[u8], key_version: u32) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| anyhow::anyhow!("ChaCha20 encryption failed: {}", e))?;

        // Формат: [version(4)] + [nonce(12)] + [ciphertext]
        let mut result = Vec::with_capacity(4 + 12 + ciphertext.len());
        result.extend_from_slice(&key_version.to_le_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Дешифрование с ChaCha20-Poly1305
    fn decrypt_with_chacha20(&self, key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 16 { // 4 bytes version + 12 bytes nonce
            return Err(anyhow::anyhow!("Encrypted data too short for ChaCha20"));
        }

        let (version_bytes, rest) = encrypted_data.split_at(4);
        let (nonce_bytes, ciphertext) = rest.split_at(12);

        let _version = u32::from_le_bytes(version_bytes.try_into().unwrap());
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = ChaCha20Poly1305::new(key.into());
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("ChaCha20 decryption failed: {}", e))
    }

    /// Шифрование с AES-256-GCM
    fn encrypt_with_aes256(&self, key: &[u8; 32], data: &[u8], key_version: u32) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {}", e))?;

        // Формат: [version(4)] + [nonce(12)] + [ciphertext]
        let mut result = Vec::with_capacity(4 + 12 + ciphertext.len());
        result.extend_from_slice(&key_version.to_le_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Дешифрование с AES-256-GCM
    fn decrypt_with_aes256(&self, key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 16 {
            return Err(anyhow::anyhow!("Encrypted data too short for AES-256-GCM"));
        }

        let (version_bytes, rest) = encrypted_data.split_at(4);
        let (nonce_bytes, ciphertext) = rest.split_at(12);

        let _version = u32::from_le_bytes(version_bytes.try_into().unwrap());
        let nonce = AesNonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new(key.into());
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM decryption failed: {}", e))
    }

    /// Шифрование с AES-128-GCM
    fn encrypt_with_aes128(&self, key: &[u8; 32], data: &[u8], key_version: u32) -> Result<Vec<u8>> {
        // Используем первые 16 байт ключа для AES-128
        let aes128_key = &key[..16];
        let cipher = Aes128Gcm::new(aes128_key.into());
        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| anyhow::anyhow!("AES-128-GCM encryption failed: {}", e))?;

        // Формат: [version(4)] + [nonce(12)] + [ciphertext]
        let mut result = Vec::with_capacity(4 + 12 + ciphertext.len());
        result.extend_from_slice(&key_version.to_le_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Дешифрование с AES-128-GCM
    fn decrypt_with_aes128(&self, key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 16 {
            return Err(anyhow::anyhow!("Encrypted data too short for AES-128-GCM"));
        }

        let (version_bytes, rest) = encrypted_data.split_at(4);
        let (nonce_bytes, ciphertext) = rest.split_at(12);

        let _version = u32::from_le_bytes(version_bytes.try_into().unwrap());
        let nonce = AesNonce::from_slice(nonce_bytes);

        // Используем первые 16 байт ключа для AES-128
        let aes128_key = &key[..16];
        let cipher = Aes128Gcm::new(aes128_key.into());
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-128-GCM decryption failed: {}", e))
    }

    /// Проверка необходимости ротации ключа
    fn check_key_rotation(&self) -> Result<()> {
        if let Some(interval) = self.key_rotation_interval {
            if let Some(last_rotation) = *self.last_key_rotation.read() {
                if last_rotation.elapsed() > interval {
                    return self.rotate_key_internal();
                }
            }
        }
        Ok(())
    }

    /// Внутренняя ротация ключа
    fn rotate_key_internal(&self) -> Result<()> {
        debug!("Performing automatic key rotation");

        // Генерируем новый ключ из старого с помощью HKDF
        let old_key = *self.key.read();
        let salt = format!("sharp-rotation-{}",
                           SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()).into_bytes();
        let info = b"SHARP-256 key rotation";

        let new_key = super::utils::derive_key(&old_key, &salt, info)?;

        // Обновляем ключ и версию
        *self.key.write() = new_key;
        *self.key_version.write() += 1;
        *self.last_key_rotation.write() = Some(Instant::now());

        self.stats.write().record_key_rotation();

        debug!("Key rotation completed, new version: {}", *self.key_version.read());

        // Очищаем старый ключ из памяти
        let mut old_key_mut = old_key;
        super::utils::secure_zero(&mut old_key_mut);

        Ok(())
    }

    /// Ручная ротация ключа
    pub fn rotate_key(&self, new_key: Option<[u8; 32]>) -> Result<()> {
        debug!("Performing manual key rotation");

        let key = if let Some(key) = new_key {
            if !super::utils::validate_key_strength(&key) {
                return Err(anyhow::anyhow!("New key is too weak"));
            }
            key
        } else {
            super::utils::generate_random_key()
        };

        let old_key = *self.key.read();

        *self.key.write() = key;
        *self.key_version.write() += 1;
        *self.last_key_rotation.write() = Some(Instant::now());

        self.stats.write().record_key_rotation();

        debug!("Manual key rotation completed, new version: {}", *self.key_version.read());

        // Очищаем старый ключ из памяти
        let mut old_key_mut = old_key;
        super::utils::secure_zero(&mut old_key_mut);

        Ok(())
    }

    /// Получение текущего алгоритма
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Получение версии ключа
    pub fn key_version(&self) -> u32 {
        *self.key_version.read()
    }

    /// Получение статистики
    pub fn get_stats(&self) -> EncryptionStats {
        self.stats.read().clone()
    }

    /// Получение информации о производительности
    pub fn get_performance_info(&self) -> PerformanceInfo {
        let stats = self.stats.read();
        PerformanceInfo {
            algorithm: self.algorithm,
            headers_processed: stats.headers_encrypted + stats.headers_decrypted,
            average_encrypt_time: stats.average_encrypt_time(),
            average_decrypt_time: stats.average_decrypt_time(),
            error_rate: if stats.headers_encrypted + stats.headers_decrypted > 0 {
                (stats.encryption_errors + stats.decryption_errors) as f64 /
                    (stats.headers_encrypted + stats.headers_decrypted) as f64
            } else {
                0.0
            },
            key_rotations: stats.key_rotations,
        }
    }

    /// Сброс статистики
    pub fn reset_stats(&self) {
        *self.stats.write() = EncryptionStats::default();
        debug!("Encryption statistics reset");
    }
}

/// Информация о производительности шифрования
#[cfg(feature = "relay-encryption")]
#[derive(Debug, Clone)]
pub struct PerformanceInfo {
    pub algorithm: EncryptionAlgorithm,
    pub headers_processed: u64,
    pub average_encrypt_time: Duration,
    pub average_decrypt_time: Duration,
    pub error_rate: f64,
    pub key_rotations: u64,
}

/// Реализация Encryptor для HeaderCrypto
#[cfg(feature = "relay-encryption")]
#[async_trait]
impl Encryptor for HeaderCrypto {
    async fn encrypt(&self, data: &[u8]) -> Result<EncryptionResult> {
        let encrypted_data = self.encrypt_header_bytes(data)?;

        Ok(EncryptionResult {
            encrypted_data: encrypted_data[16..].to_vec(), // Убираем version + nonce для совместимости
            nonce: encrypted_data[4..16].to_vec(), // Извлекаем nonce
            metadata: EncryptionMetadata {
                algorithm: Some(self.algorithm),
                timestamp: Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()),
                key_version: Some(self.key_version()),
                obfuscation_applied: false,
            },
        })
    }

    async fn decrypt(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        // Восстанавливаем полный формат для дешифрования
        let key_version = encrypted.metadata.key_version.unwrap_or(1);
        let mut full_data = Vec::new();
        full_data.extend_from_slice(&key_version.to_le_bytes());
        full_data.extend_from_slice(&encrypted.nonce);
        full_data.extend_from_slice(&encrypted.encrypted_data);

        self.decrypt_header_bytes(&full_data)
    }

    async fn encrypt_header(&self, header: &[u8]) -> Result<EncryptionResult> {
        self.encrypt(header).await
    }

    async fn decrypt_header(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        self.decrypt(encrypted).await
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    async fn rotate_key(&mut self) -> Result<()> {
        self.rotate_key(None)
    }
}

/// Конкретные реализации encryptor-ов для каждого алгоритма
#[cfg(feature = "relay-encryption")]
pub struct ChaCha20Encryptor {
    header_crypto: HeaderCrypto,
}

#[cfg(feature = "relay-encryption")]
impl ChaCha20Encryptor {
    pub fn new(config: EncryptionConfig) -> Result<Self> {
        if config.algorithm != EncryptionAlgorithm::ChaCha20Poly1305 {
            return Err(anyhow::anyhow!("Invalid algorithm for ChaCha20Encryptor"));
        }

        let header_crypto = HeaderCrypto::with_config(config)?;
        Ok(Self { header_crypto })
    }
}

#[cfg(feature = "relay-encryption")]
#[async_trait]
impl Encryptor for ChaCha20Encryptor {
    async fn encrypt(&self, data: &[u8]) -> Result<EncryptionResult> {
        self.header_crypto.encrypt(data).await
    }

    async fn decrypt(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        self.header_crypto.decrypt(encrypted).await
    }

    async fn encrypt_header(&self, header: &[u8]) -> Result<EncryptionResult> {
        self.header_crypto.encrypt_header(header).await
    }

    async fn decrypt_header(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        self.header_crypto.decrypt_header(encrypted).await
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::ChaCha20Poly1305
    }

    async fn rotate_key(&mut self) -> Result<()> {
        self.header_crypto.rotate_key(None)
    }
}

/// AES-256-GCM Encryptor
#[cfg(feature = "relay-encryption")]
pub struct AesGcm256Encryptor {
    header_crypto: HeaderCrypto,
}

#[cfg(feature = "relay-encryption")]
impl AesGcm256Encryptor {
    pub fn new(config: EncryptionConfig) -> Result<Self> {
        if config.algorithm != EncryptionAlgorithm::AesGcm256 {
            return Err(anyhow::anyhow!("Invalid algorithm for AesGcm256Encryptor"));
        }

        let header_crypto = HeaderCrypto::with_config(config)?;
        Ok(Self { header_crypto })
    }
}

#[cfg(feature = "relay-encryption")]
#[async_trait]
impl Encryptor for AesGcm256Encryptor {
    async fn encrypt(&self, data: &[u8]) -> Result<EncryptionResult> {
        self.header_crypto.encrypt(data).await
    }

    async fn decrypt(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        self.header_crypto.decrypt(encrypted).await
    }

    async fn encrypt_header(&self, header: &[u8]) -> Result<EncryptionResult> {
        self.header_crypto.encrypt_header(header).await
    }

    async fn decrypt_header(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        self.header_crypto.decrypt_header(encrypted).await
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::AesGcm256
    }

    async fn rotate_key(&mut self) -> Result<()> {
        self.header_crypto.rotate_key(None)
    }
}

/// AES-128-GCM Encryptor
#[cfg(feature = "relay-encryption")]
pub struct AesGcm128Encryptor {
    header_crypto: HeaderCrypto,
}

#[cfg(feature = "relay-encryption")]
impl AesGcm128Encryptor {
    pub fn new(config: EncryptionConfig) -> Result<Self> {
        if config.algorithm != EncryptionAlgorithm::AesGcm128 {
            return Err(anyhow::anyhow!("Invalid algorithm for AesGcm128Encryptor"));
        }

        let header_crypto = HeaderCrypto::with_config(config)?;
        Ok(Self { header_crypto })
    }
}

#[cfg(feature = "relay-encryption")]
#[async_trait]
impl Encryptor for AesGcm128Encryptor {
    async fn encrypt(&self, data: &[u8]) -> Result<EncryptionResult> {
        self.header_crypto.encrypt(data).await
    }

    async fn decrypt(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        self.header_crypto.decrypt(encrypted).await
    }

    async fn encrypt_header(&self, header: &[u8]) -> Result<EncryptionResult> {
        self.header_crypto.encrypt_header(header).await
    }

    async fn decrypt_header(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>> {
        self.header_crypto.decrypt_header(encrypted).await
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::AesGcm128
    }

    async fn rotate_key(&mut self) -> Result<()> {
        self.header_crypto.rotate_key(None)
    }
}

#[cfg(test)]
#[cfg(feature = "relay-encryption")]
mod tests {
    use super::*;
    use crate::protocol::{packet::PacketHeader, constants::*};

    #[test]
    fn test_header_crypto_creation() {
        let key = super::super::utils::generate_random_key();
        let crypto = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::ChaCha20Poly1305).unwrap();

        assert_eq!(crypto.algorithm(), EncryptionAlgorithm::ChaCha20Poly1305);
        assert_eq!(crypto.key_version(), 1);
    }

    #[test]
    fn test_header_encryption_decryption() {
        let key = super::super::utils::generate_random_key();
        let crypto = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::ChaCha20Poly1305).unwrap();

        // Создаем тестовый заголовок
        let mut header = PacketHeader::new(PacketType::Data);
        header.batch_number = 12345;
        header.packet_in_batch = 67;
        header.payload_length = 1024;
        header.sequence = 999;

        // Шифруем заголовок
        let encrypted = crypto.encrypt_header(&header).unwrap();
        assert!(encrypted.len() > SHARP_HEADER_SIZE); // Должен быть больше из-за nonce и version

        // Дешифруем заголовок
        let decrypted_header = crypto.decrypt_header(&encrypted).unwrap();

        // Проверяем что данные совпадают
        assert_eq!(header.batch_number, decrypted_header.batch_number);
        assert_eq!(header.packet_in_batch, decrypted_header.packet_in_batch);
        assert_eq!(header.payload_length, decrypted_header.payload_length);
        assert_eq!(header.sequence, decrypted_header.sequence);
    }

    #[test]
    fn test_header_bytes_encryption() {
        let key = super::super::utils::generate_random_key();
        let crypto = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::AesGcm256).unwrap();

        let test_data = vec![0xAA; SHARP_HEADER_SIZE];

        // Шифруем
        let encrypted = crypto.encrypt_header_bytes(&test_data).unwrap();
        assert!(encrypted.len() > test_data.len());

        // Дешифруем
        let decrypted = crypto.decrypt_header_bytes(&encrypted).unwrap();
        assert_eq!(test_data, decrypted);
    }

    #[test]
    fn test_different_algorithms() {
        let key = super::super::utils::generate_random_key();
        let test_data = vec![0x55; SHARP_HEADER_SIZE];

        // Тестируем все алгоритмы
        let algorithms = [
            HeaderEncryptionAlgorithm::ChaCha20Poly1305,
            HeaderEncryptionAlgorithm::AesGcm256,
            HeaderEncryptionAlgorithm::AesGcm128,
        ];

        for algorithm in algorithms {
            let crypto = HeaderCrypto::new(key, algorithm).unwrap();

            let encrypted = crypto.encrypt_header_bytes(&test_data).unwrap();
            let decrypted = crypto.decrypt_header_bytes(&encrypted).unwrap();

            assert_eq!(test_data, decrypted, "Algorithm {:?} failed", algorithm);
        }
    }

    #[test]
    fn test_key_rotation() {
        let key = super::super::utils::generate_random_key();
        let crypto = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::ChaCha20Poly1305).unwrap();

        let initial_version = crypto.key_version();

        // Выполняем ротацию ключа
        crypto.rotate_key(None).unwrap();

        assert_eq!(crypto.key_version(), initial_version + 1);
    }

    #[test]
    fn test_weak_key_rejection() {
        let weak_key = [0u8; 32]; // Все нули
        let result = HeaderCrypto::new(weak_key, HeaderEncryptionAlgorithm::ChaCha20Poly1305);

        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_stats() {
        let key = super::super::utils::generate_random_key();
        let crypto = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::ChaCha20Poly1305).unwrap();

        let test_data = vec![0x77; SHARP_HEADER_SIZE];

        // Выполняем несколько операций
        for _ in 0..5 {
            let encrypted = crypto.encrypt_header_bytes(&test_data).unwrap();
            let _ = crypto.decrypt_header_bytes(&encrypted).unwrap();
        }

        let stats = crypto.get_stats();
        assert_eq!(stats.headers_encrypted, 5);
        assert_eq!(stats.headers_decrypted, 5);
        assert!(stats.total_encrypt_time > Duration::ZERO);
        assert!(stats.total_decrypt_time > Duration::ZERO);
    }

    #[test]
    fn test_performance_info() {
        let key = super::super::utils::generate_random_key();
        let crypto = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::AesGcm128).unwrap();

        let test_data = vec![0x88; SHARP_HEADER_SIZE];

        // Выполняем операции
        for _ in 0..3 {
            let encrypted = crypto.encrypt_header_bytes(&test_data).unwrap();
            let _ = crypto.decrypt_header_bytes(&encrypted).unwrap();
        }

        let perf_info = crypto.get_performance_info();
        assert_eq!(perf_info.algorithm, EncryptionAlgorithm::AesGcm128);
        assert_eq!(perf_info.headers_processed, 6); // 3 encrypt + 3 decrypt
        assert!(perf_info.average_encrypt_time > Duration::ZERO);
        assert!(perf_info.average_decrypt_time > Duration::ZERO);
        assert_eq!(perf_info.error_rate, 0.0);
    }

    #[tokio::test]
    async fn test_encryptor_trait() {
        let config = EncryptionConfig {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key: super::super::utils::generate_random_key(),
            ..Default::default()
        };

        let crypto = HeaderCrypto::with_config(config).unwrap();
        let test_data = vec![0x99; SHARP_HEADER_SIZE];

        // Тестируем async методы
        let encrypted_result = crypto.encrypt(&test_data).await.unwrap();
        let decrypted = crypto.decrypt(&encrypted_result).await.unwrap();

        assert_eq!(test_data, decrypted);
        assert_eq!(encrypted_result.metadata.algorithm, Some(EncryptionAlgorithm::ChaCha20Poly1305));
        assert!(encrypted_result.metadata.timestamp.is_some());
        assert_eq!(encrypted_result.metadata.key_version, Some(1));
    }

    #[test]
    fn test_invalid_data_size() {
        let key = super::super::utils::generate_random_key();
        let crypto = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::ChaCha20Poly1305).unwrap();

        // Тестируем с неправильным размером данных
        let wrong_size_data = vec![0xAA; 10]; // Меньше чем SHARP_HEADER_SIZE

        let result = crypto.encrypt_header_bytes(&wrong_size_data);
        // Должно работать для произвольных размеров в encrypt_header_bytes
        assert!(result.is_ok());

        // Но decrypt должен работать корректно
        let encrypted = result.unwrap();
        let decrypted = crypto.decrypt_header_bytes(&encrypted).unwrap();
        assert_eq!(wrong_size_data, decrypted);
    }

    #[test]
    fn test_cross_algorithm_incompatibility() {
        let key = super::super::utils::generate_random_key();
        let crypto1 = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::ChaCha20Poly1305).unwrap();
        let crypto2 = HeaderCrypto::new(key, HeaderEncryptionAlgorithm::AesGcm256).unwrap();

        let test_data = vec![0xBB; SHARP_HEADER_SIZE];

        // Шифруем одним алгоритмом
        let encrypted = crypto1.encrypt_header_bytes(&test_data).unwrap();

        // Пытаемся дешифровать другим
        let result = crypto2.decrypt_header_bytes(&encrypted);
        assert!(result.is_err()); // Должно не удаться
    }
}