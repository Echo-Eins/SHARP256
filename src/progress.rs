use std::sync::Arc;

/// Информация о прогрессе передачи
#[derive(Debug, Clone)]
pub struct ProgressInfo {
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub current_speed_mbps: f64,
    pub average_speed_mbps: f64,
    pub eta_seconds: u64,
    pub current_batch: u32,
    pub total_batches: u32,
}

/// Callback для обновления прогресса
pub type ProgressCallback = Arc<dyn Fn(ProgressInfo) + Send + Sync>;

/// События передачи
#[derive(Debug, Clone)]
pub enum TransferEvent {
    Started {
        file_name: String,
        file_size: u64,
    },
    Progress(ProgressInfo),
    Completed {
        total_time_ms: u64,
        average_speed_mbps: f64,
    },
    Failed {
        error: String,
    },
    IncomingRequest {
        from: String,
        file_name: String,
        file_size: u64,
    },
}

/// Callback для событий передачи
pub type EventCallback = Arc<dyn Fn(TransferEvent) + Send + Sync>;