use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use crate::protocol::ack::SaoParams;
use base64::{Engine as _, engine::general_purpose};

/// Состояние передачи файла для возможности восстановления
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    pub protocol_version: String,
    pub file_name: String,
    pub file_size: u64,
    pub total_packets_sent: u64,
    pub last_batch_number: u32,
    pub last_packet_in_batch: u16,
    pub bytes_transferred: u64,
    pub last_data_fragment: String, // Base64 последних 1KB данных
    pub timestamp: DateTime<Utc>,
    pub sao_params: Option<SaoParams>,
    pub is_sender: bool,
    pub peer_address: String,
    pub resume_token: String, // Уникальный токен для возобновления
    pub partial_file_hash: Option<String>, // Хеш переданной части
}

impl TransferState {
    pub fn new(
        file_name: String,
        file_size: u64,
        is_sender: bool,
        peer_address: String,
    ) -> Self {
        #[cfg(feature = "nat-traversal")]
        let resume_token: String = {
            use rand::Rng;
            rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(32)
                .map(char::from)
                .collect()
        };
        
        #[cfg(not(feature = "nat-traversal"))]
        let resume_token = format!("token_{}", chrono::Utc::now().timestamp());
        
        Self {
            protocol_version: "SHARP-256".to_string(),
            file_name,
            file_size,
            total_packets_sent: 0,
            last_batch_number: 0,
            last_packet_in_batch: 0,
            bytes_transferred: 0,
            last_data_fragment: String::new(),
            timestamp: Utc::now(),
            sao_params: None,
            is_sender,
            peer_address,
            resume_token,
            partial_file_hash: None,
        }
    }
    
    /// Обновление состояния после отправки/получения пакета
    pub fn update_progress(
        &mut self,
        batch_number: u32,
        packet_in_batch: u16,
        bytes: u64,
        last_data: Option<&[u8]>,
    ) {
        self.last_batch_number = batch_number;
        self.last_packet_in_batch = packet_in_batch;
        self.bytes_transferred += bytes;
        self.total_packets_sent += 1;
        self.timestamp = Utc::now();
        
        // Сохраняем последний фрагмент данных для поиска позиции при восстановлении
        if let Some(data) = last_data {
            let fragment_size = data.len().min(1024);
            let fragment = &data[data.len() - fragment_size..];
            self.last_data_fragment = general_purpose::STANDARD.encode(fragment);
        }
    }
    
    /// Сохранение состояния в файл
    pub fn save(&self, state_dir: &Path) -> Result<PathBuf> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("Failed to create state directory: {:?}", state_dir))?;
        
        let file_stem = Path::new(&self.file_name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        
        let state_file = state_dir.join(format!(
            "{}_{}_{}.state",
            file_stem,
            if self.is_sender { "send" } else { "recv" },
            self.timestamp.format("%Y%m%d_%H%M%S")
        ));
        
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize transfer state")?;
        
        fs::write(&state_file, json)
            .with_context(|| format!("Failed to write state file: {:?}", state_file))?;
        
        Ok(state_file)
    }
    
    /// Загрузка состояния из файла
    pub fn load(state_file: &Path) -> Result<Self> {
        let json = fs::read_to_string(state_file)
            .with_context(|| format!("Failed to read state file: {:?}", state_file))?;
        
        let state = serde_json::from_str(&json)
            .context("Failed to deserialize transfer state")?;
        
        Ok(state)
    }
    
    /// Поиск последнего состояния для файла
    pub fn find_latest(state_dir: &Path, file_name: &str, is_sender: bool) -> Result<Option<PathBuf>> {
        if !state_dir.exists() {
            return Ok(None);
        }
        
        let file_stem = Path::new(file_name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        
        let pattern = format!(
            "{}_{}",
            file_stem,
            if is_sender { "send" } else { "recv" }
        );
        
        let mut latest: Option<(PathBuf, DateTime<Utc>)> = None;
        
        for entry in fs::read_dir(state_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("state") {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with(&pattern) {
                        // Пытаемся загрузить и проверить timestamp
                        if let Ok(state) = Self::load(&path) {
                            match &mut latest {
                                Some((_, latest_time)) if state.timestamp > *latest_time => {
                                    latest = Some((path, state.timestamp));
                                }
                                None => {
                                    latest = Some((path, state.timestamp));
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        
        Ok(latest.map(|(path, _)| path))
    }
    
    /// Удаление файла состояния после успешной передачи
    pub fn cleanup(state_file: &Path) -> Result<()> {
        if state_file.exists() {
            fs::remove_file(state_file)
                .with_context(|| format!("Failed to remove state file: {:?}", state_file))?;
        }
        Ok(())
    }
    
    /// Поиск позиции в файле по последнему фрагменту данных
    pub fn find_resume_position(&self, file_manager: &crate::file::FileManager) -> Result<Option<u64>> {
        if self.last_data_fragment.is_empty() {
            return Ok(None);
        }
        
        let fragment = general_purpose::STANDARD.decode(&self.last_data_fragment)
            .context("Failed to decode last data fragment")?;
        
        if fragment.is_empty() {
            return Ok(None);
        }
        
        // Размер окна поиска (начинаем с предполагаемой позиции минус 10MB)
        let search_window = 10 * 1024 * 1024;
        let estimated_pos = self.bytes_transferred.saturating_sub(fragment.len() as u64);
        let search_start = estimated_pos.saturating_sub(search_window);
        
        // Буфер для чтения
        let mut buffer = vec![0u8; fragment.len() + 1024];
        let mut position = search_start;
        
        // Поиск фрагмента в файле
        while position < file_manager.size() {
            let read_size = buffer.len().min((file_manager.size() - position) as usize);
            if read_size < fragment.len() {
                break;
            }
            
            let data = file_manager.read_at(position, read_size)?;
            
            // Ищем фрагмент в прочитанных данных
            if let Some(offset) = data.windows(fragment.len())
                .position(|window| window == fragment.as_slice()) {
                // Нашли позицию
                return Ok(Some(position + offset as u64 + fragment.len() as u64));
            }
            
            // Сдвигаемся вперед, оставляя перекрытие
            position += (read_size - fragment.len()) as u64;
        }
        
        Ok(None)
    }
}

/// Менеджер состояний передачи
pub struct StateManager {
    state_dir: PathBuf,
}

impl StateManager {
    pub fn new() -> Result<Self> {
        let state_dir = dirs::data_dir()
            .ok_or_else(|| anyhow::anyhow!("Failed to get data directory"))?
            .join("sharp-256")
            .join("states");
        
        fs::create_dir_all(&state_dir)?;
        
        Ok(Self { state_dir })
    }
    
    /// Сохранение состояния
    pub fn save_state(&self, state: &TransferState) -> Result<PathBuf> {
        state.save(&self.state_dir)
    }
    
    /// Поиск состояния для восстановления
    pub fn find_state(&self, file_name: &str, is_sender: bool) -> Result<Option<TransferState>> {
        if let Some(state_file) = TransferState::find_latest(&self.state_dir, file_name, is_sender)? {
            let state = TransferState::load(&state_file)?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }
    
    /// Очистка старых состояний (старше 7 дней)
    pub fn cleanup_old_states(&self) -> Result<()> {
        let cutoff = Utc::now() - chrono::Duration::days(7);
        
        for entry in fs::read_dir(&self.state_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("state") {
                if let Ok(state) = TransferState::load(&path) {
                    if state.timestamp < cutoff {
                        fs::remove_file(&path)?;
                    }
                }
            }
        }
        
        Ok(())
    }
}