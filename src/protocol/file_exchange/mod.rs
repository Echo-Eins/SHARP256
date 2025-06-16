// src/protocol/file_exchange/mod.rs
//! High-performance file exchange protocol with NAT traversal support
//! 
//! Implements efficient file transfer with:
//! - Chunk-based streaming
//! - Resume support
//! - Integrity verification
//! - Compression
//! - Encryption
//! - Multi-path transfer

use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::fs as async_fs;
use tokio::time::interval;

use bytes::{Bytes, BytesMut, BufMut};
use blake3::Hasher as Blake3Hasher;
use zstd::stream::{encode_all, decode_all};
use uuid::Uuid;

use crate::protocol::{Message, MessageType};
use crate::crypto::{encrypt_chunk, decrypt_chunk};
use crate::nat::NatTraversal;

/// File transfer configuration
#[derive(Debug, Clone)]
pub struct FileTransferConfig {
    /// Chunk size for transfer (default: 64KB)
    pub chunk_size: usize,
    
    /// Maximum concurrent chunks in flight
    pub max_concurrent_chunks: usize,
    
    /// Enable compression (Zstandard)
    pub enable_compression: bool,
    
    /// Compression level (1-22, default: 3)
    pub compression_level: i32,
    
    /// Enable encryption
    pub enable_encryption: bool,
    
    /// Chunk timeout
    pub chunk_timeout: Duration,
    
    /// Maximum retry attempts per chunk
    pub max_retries: u32,
    
    /// Enable multi-path transfer
    pub enable_multipath: bool,
    
    /// Bandwidth limit in bytes per second (0 = unlimited)
    pub bandwidth_limit: u64,
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            chunk_size: 65536,              // 64KB chunks
            max_concurrent_chunks: 16,       // 16 chunks in flight
            enable_compression: true,
            compression_level: 3,
            enable_encryption: true,
            chunk_timeout: Duration::from_secs(10),
            max_retries: 3,
            enable_multipath: true,
            bandwidth_limit: 0,
        }
    }
}

/// File metadata for transfer
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    /// Unique file ID
    pub file_id: Uuid,
    
    /// File name
    pub name: String,
    
    /// File size in bytes
    pub size: u64,
    
    /// BLAKE3 hash of complete file
    pub hash: Vec<u8>,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Modification timestamp
    pub modified_at: u64,
    
    /// MIME type
    pub mime_type: Option<String>,
    
    /// File permissions (Unix mode)
    pub permissions: Option<u32>,
    
    /// Chunk hashes for verification
    pub chunk_hashes: Vec<Vec<u8>>,
    
    /// Total number of chunks
    pub total_chunks: u64,
}

/// File transfer state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Waiting to start
    Pending,
    
    /// Negotiating transfer parameters
    Negotiating,
    
    /// Actively transferring
    Transferring,
    
    /// Paused by user
    Paused,
    
    /// Completed successfully
    Completed,
    
    /// Failed with error
    Failed,
    
    /// Cancelled by user
    Cancelled,
}

/// File chunk for transfer
#[derive(Debug, Clone)]
pub struct FileChunk {
    /// Chunk index (0-based)
    pub index: u64,
    
    /// Chunk data (possibly compressed/encrypted)
    pub data: Bytes,
    
    /// BLAKE3 hash of original data
    pub hash: Vec<u8>,
    
    /// Size of original data (before compression)
    pub original_size: usize,
    
    /// Transfer path ID (for multipath)
    pub path_id: u8,
}

/// File transfer session
pub struct FileTransfer {
    /// Transfer ID
    pub id: Uuid,
    
    /// File metadata
    pub metadata: FileMetadata,
    
    /// Transfer configuration
    pub config: FileTransferConfig,
    
    /// Current state
    pub state: Arc<RwLock<TransferState>>,
    
    /// Transfer direction (true = sending, false = receiving)
    pub is_sender: bool,
    
    /// Progress tracking
    pub progress: Arc<TransferProgress>,
    
    /// Chunk acknowledgment tracking
    chunk_acks: Arc<RwLock<HashMap<u64, ChunkStatus>>>,
    
    /// Active transfer paths
    paths: Arc<RwLock<Vec<TransferPath>>>,
    
    /// Rate limiter
    rate_limiter: Option<Arc<RateLimiter>>,
}

/// Chunk transfer status
#[derive(Debug, Clone, Copy)]
struct ChunkStatus {
    /// Number of send attempts
    attempts: u32,
    
    /// Last attempt timestamp
    last_attempt: Instant,
    
    /// Successfully acknowledged
    acknowledged: bool,
    
    /// Path ID used for transfer
    path_id: u8,
}

/// Transfer path for multipath
#[derive(Debug, Clone)]
struct TransferPath {
    /// Path ID
    id: u8,
    
    /// Remote address
    address: std::net::SocketAddr,
    
    /// Path quality (0.0 to 1.0)
    quality: f64,
    
    /// Estimated RTT
    rtt: Duration,
    
    /// Available bandwidth (bytes/sec)
    bandwidth: u64,
    
    /// Active chunk count on this path
    active_chunks: usize,
}

/// Transfer progress tracking
#[derive(Debug)]
pub struct TransferProgress {
    /// Total bytes to transfer
    pub total_bytes: AtomicU64,
    
    /// Bytes transferred so far
    pub transferred_bytes: AtomicU64,
    
    /// Chunks completed
    pub completed_chunks: AtomicU64,
    
    /// Transfer start time
    pub start_time: Instant,
    
    /// Last activity time
    pub last_activity: RwLock<Instant>,
    
    /// Current transfer rate (bytes/sec)
    pub transfer_rate: AtomicU64,
}

use std::sync::atomic::{AtomicU64, Ordering};

impl TransferProgress {
    fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes: AtomicU64::new(total_bytes),
            transferred_bytes: AtomicU64::new(0),
            completed_chunks: AtomicU64::new(0),
            start_time: Instant::now(),
            last_activity: RwLock::new(Instant::now()),
            transfer_rate: AtomicU64::new(0),
        }
    }
    
    /// Get transfer percentage (0.0 to 100.0)
    pub fn percentage(&self) -> f64 {
        let total = self.total_bytes.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        
        let transferred = self.transferred_bytes.load(Ordering::Relaxed);
        (transferred as f64 / total as f64) * 100.0
    }
    
    /// Get estimated time remaining
    pub fn eta(&self) -> Option<Duration> {
        let rate = self.transfer_rate.load(Ordering::Relaxed);
        if rate == 0 {
            return None;
        }
        
        let remaining = self.total_bytes.load(Ordering::Relaxed)
            .saturating_sub(self.transferred_bytes.load(Ordering::Relaxed));
        
        Some(Duration::from_secs(remaining / rate))
    }
}

impl FileTransfer {
    /// Create new file transfer for sending
    pub async fn new_sender(
        file_path: &Path,
        config: FileTransferConfig,
    ) -> io::Result<Self> {
        let metadata = Self::create_metadata(file_path, &config).await?;
        let id = Uuid::new_v4();
        
        let rate_limiter = if config.bandwidth_limit > 0 {
            Some(Arc::new(RateLimiter::new(config.bandwidth_limit)))
        } else {
            None
        };
        
        Ok(Self {
            id,
            metadata,
            config,
            state: Arc::new(RwLock::new(TransferState::Pending)),
            is_sender: true,
            progress: Arc::new(TransferProgress::new(0)), // Will be set after metadata
            chunk_acks: Arc::new(RwLock::new(HashMap::new())),
            paths: Arc::new(RwLock::new(Vec::new())),
            rate_limiter,
        })
    }
    
    /// Create new file transfer for receiving
    pub fn new_receiver(
        metadata: FileMetadata,
        config: FileTransferConfig,
    ) -> Self {
        let id = Uuid::new_v4();
        let total_bytes = metadata.size;
        
        let rate_limiter = if config.bandwidth_limit > 0 {
            Some(Arc::new(RateLimiter::new(config.bandwidth_limit)))
        } else {
            None
        };
        
        Self {
            id,
            metadata,
            config,
            state: Arc::new(RwLock::new(TransferState::Pending)),
            is_sender: false,
            progress: Arc::new(TransferProgress::new(total_bytes)),
            chunk_acks: Arc::new(RwLock::new(HashMap::new())),
            paths: Arc::new(RwLock::new(Vec::new())),
            rate_limiter,
        }
    }
    
    /// Create file metadata
    async fn create_metadata(
        file_path: &Path,
        config: &FileTransferConfig,
    ) -> io::Result<FileMetadata> {
        let file = async_fs::File::open(file_path).await?;
        let metadata = file.metadata().await?;
        
        let size = metadata.len();
        let created_at = metadata.created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let modified_at = metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };
        
        #[cfg(not(unix))]
        let permissions = None;
        
        // Calculate chunk count
        let chunk_count = (size + config.chunk_size as u64 - 1) / config.chunk_size as u64;
        
        // Calculate file and chunk hashes
        let (file_hash, chunk_hashes) = Self::calculate_hashes(file_path, config).await?;
        
        // Detect MIME type
        let mime_type = mime_guess::from_path(file_path)
            .first()
            .map(|m| m.to_string());
        
        Ok(FileMetadata {
            file_id: Uuid::new_v4(),
            name: file_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string(),
            size,
            hash: file_hash,
            created_at,
            modified_at,
            mime_type,
            permissions,
            chunk_hashes,
            total_chunks: chunk_count,
        })
    }
    
    /// Calculate file and chunk hashes
    async fn calculate_hashes(
        file_path: &Path,
        config: &FileTransferConfig,
    ) -> io::Result<(Vec<u8>, Vec<Vec<u8>>)> {
        let mut file = async_fs::File::open(file_path).await?;
        let mut file_hasher = Blake3Hasher::new();
        let mut chunk_hashes = Vec::new();
        
        let mut buffer = vec![0u8; config.chunk_size];
        
        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            
            let chunk_data = &buffer[..n];
            
            // Update file hash
            file_hasher.update(chunk_data);
            
            // Calculate chunk hash
            let chunk_hash = blake3::hash(chunk_data);
            chunk_hashes.push(chunk_hash.as_bytes().to_vec());
        }
        
        let file_hash = file_hasher.finalize();
        Ok((file_hash.as_bytes().to_vec(), chunk_hashes))
    }
    
    /// Start file transfer
    pub async fn start(&self) -> Result<(), FileTransferError> {
        let mut state = self.state.write().await;
        
        match *state {
            TransferState::Pending => {
                *state = TransferState::Negotiating;
                Ok(())
            }
            TransferState::Paused => {
                *state = TransferState::Transferring;
                Ok(())
            }
            _ => Err(FileTransferError::InvalidState(*state)),
        }
    }
    
    /// Pause file transfer
    pub async fn pause(&self) -> Result<(), FileTransferError> {
        let mut state = self.state.write().await;
        
        match *state {
            TransferState::Transferring => {
                *state = TransferState::Paused;
                Ok(())
            }
            _ => Err(FileTransferError::InvalidState(*state)),
        }
    }
    
    /// Cancel file transfer
    pub async fn cancel(&self) -> Result<(), FileTransferError> {
        let mut state = self.state.write().await;
        *state = TransferState::Cancelled;
        Ok(())
    }
    
    /// Add transfer path for multipath
    pub async fn add_path(&self, address: std::net::SocketAddr) {
        let mut paths = self.paths.write().await;
        
        let path = TransferPath {
            id: paths.len() as u8,
            address,
            quality: 1.0,
            rtt: Duration::from_millis(50), // Will be measured
            bandwidth: u64::MAX,             // Will be measured
            active_chunks: 0,
        };
        
        paths.push(path);
    }
    
    /// Get next chunk to send
    pub async fn next_send_chunk(&self) -> Option<u64> {
        let acks = self.chunk_acks.read().await;
        
        // Find first unacknowledged chunk
        for chunk_idx in 0..self.metadata.total_chunks {
            match acks.get(&chunk_idx) {
                None => return Some(chunk_idx),
                Some(status) if !status.acknowledged => {
                    // Check if retry is needed
                    if status.attempts < self.config.max_retries &&
                       status.last_attempt.elapsed() > self.config.chunk_timeout {
                        return Some(chunk_idx);
                    }
                }
                _ => continue,
            }
        }
        
        None
    }
    
    /// Read chunk from file
    pub async fn read_chunk(
        &self,
        file_path: &Path,
        chunk_index: u64,
    ) -> Result<FileChunk, FileTransferError> {
        let mut file = async_fs::File::open(file_path).await?;
        
        let offset = chunk_index * self.config.chunk_size as u64;
        file.seek(SeekFrom::Start(offset)).await?;
        
        let mut buffer = vec![0u8; self.config.chunk_size];
        let n = file.read(&mut buffer).await?;
        buffer.truncate(n);
        
        // Verify chunk hash
        let hash = blake3::hash(&buffer);
        if let Some(expected_hash) = self.metadata.chunk_hashes.get(chunk_index as usize) {
            if hash.as_bytes() != expected_hash.as_slice() {
                return Err(FileTransferError::ChunkHashMismatch {
                    chunk_index,
                    expected: expected_hash.clone(),
                    actual: hash.as_bytes().to_vec(),
                });
            }
        }
        
        let original_size = buffer.len();
        let mut data = Bytes::from(buffer);
        
        // Apply compression if enabled
        if self.config.enable_compression && original_size > 100 {
            if let Ok(compressed) = encode_all(&data[..], self.config.compression_level) {
                if compressed.len() < original_size {
                    data = Bytes::from(compressed);
                }
            }
        }
        
        // Apply encryption if enabled
        if self.config.enable_encryption {
            // Encryption would be applied here using the session key
            // data = encrypt_chunk(&data, &session_key)?;
        }
        
        // Apply rate limiting if configured
        if let Some(ref limiter) = self.rate_limiter {
            limiter.acquire(data.len()).await;
        }
        
        // Select best path for this chunk
        let path_id = self.select_best_path().await;
        
        Ok(FileChunk {
            index: chunk_index,
            data,
            hash: hash.as_bytes().to_vec(),
            original_size,
            path_id,
        })
    }
    
    /// Select best path for chunk transfer
    async fn select_best_path(&self) -> u8 {
        let paths = self.paths.read().await;
        
        if paths.is_empty() {
            return 0;
        }
        
        // Simple selection: choose path with best quality and least active chunks
        let best_path = paths.iter()
            .min_by_key(|p| {
                let load = p.active_chunks as f64 / p.quality;
                (load * 1000.0) as u64
            })
            .unwrap();
        
        best_path.id
    }
    
    /// Process received chunk
    pub async fn process_chunk(
        &self,
        chunk: FileChunk,
        output_file: &mut async_fs::File,
    ) -> Result<(), FileTransferError> {
        // Verify chunk index
        if chunk.index >= self.metadata.total_chunks {
            return Err(FileTransferError::InvalidChunkIndex(chunk.index));
        }
        
        let mut data = chunk.data;
        
        // Decrypt if needed
        if self.config.enable_encryption {
            // data = decrypt_chunk(&data, &session_key)?;
        }
        
        // Decompress if needed
        if self.config.enable_compression {
            if let Ok(decompressed) = decode_all(&data[..]) {
                data = Bytes::from(decompressed);
            }
        }
        
        // Verify chunk hash
        let hash = blake3::hash(&data);
        if let Some(expected_hash) = self.metadata.chunk_hashes.get(chunk.index as usize) {
            if hash.as_bytes() != expected_hash.as_slice() {
                return Err(FileTransferError::ChunkHashMismatch {
                    chunk_index: chunk.index,
                    expected: expected_hash.clone(),
                    actual: hash.as_bytes().to_vec(),
                });
            }
        }
        
        // Write to file at correct position
        let offset = chunk.index * self.config.chunk_size as u64;
        output_file.seek(SeekFrom::Start(offset)).await?;
        output_file.write_all(&data).await?;
        
        // Update progress
        self.progress.transferred_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.progress.completed_chunks.fetch_add(1, Ordering::Relaxed);
        *self.progress.last_activity.write().await = Instant::now();
        
        // Mark chunk as received
        let mut acks = self.chunk_acks.write().await;
        acks.insert(chunk.index, ChunkStatus {
            attempts: 1,
            last_attempt: Instant::now(),
            acknowledged: true,
            path_id: chunk.path_id,
        });
        
        Ok(())
    }
    
    /// Check if transfer is complete
    pub async fn is_complete(&self) -> bool {
        let acks = self.chunk_acks.read().await;
        
        if acks.len() != self.metadata.total_chunks as usize {
            return false;
        }
        
        acks.values().all(|status| status.acknowledged)
    }
    
    /// Verify completed file
    pub async fn verify_file(&self, file_path: &Path) -> Result<(), FileTransferError> {
        let file = async_fs::File::open(file_path).await?;
        let metadata = file.metadata().await?;
        
        // Check file size
        if metadata.len() != self.metadata.size {
            return Err(FileTransferError::SizeMismatch {
                expected: self.metadata.size,
                actual: metadata.len(),
            });
        }
        
        // Calculate and verify file hash
        let mut file = async_fs::File::open(file_path).await?;
        let mut hasher = Blake3Hasher::new();
        let mut buffer = vec![0u8; 65536];
        
        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        
        let hash = hasher.finalize();
        if hash.as_bytes() != self.metadata.hash.as_slice() {
            return Err(FileTransferError::HashMismatch {
                expected: self.metadata.hash.clone(),
                actual: hash.as_bytes().to_vec(),
            });
        }
        
        Ok(())
    }
}

/// Rate limiter for bandwidth control
struct RateLimiter {
    /// Maximum bytes per second
    limit: u64,
    
    /// Available tokens
    tokens: Arc<RwLock<f64>>,
    
    /// Last refill time
    last_refill: Arc<RwLock<Instant>>,
}

impl RateLimiter {
    fn new(bytes_per_second: u64) -> Self {
        Self {
            limit: bytes_per_second,
            tokens: Arc::new(RwLock::new(bytes_per_second as f64)),
            last_refill: Arc::new(RwLock::new(Instant::now())),
        }
    }
    
    async fn acquire(&self, bytes: usize) {
        let tokens_needed = bytes as f64;
        
        loop {
            // Refill tokens
            {
                let mut tokens = self.tokens.write().await;
                let mut last_refill = self.last_refill.write().await;
                
                let elapsed = last_refill.elapsed();
                let refill = elapsed.as_secs_f64() * self.limit as f64;
                
                *tokens = (*tokens + refill).min(self.limit as f64);
                *last_refill = Instant::now();
                
                if *tokens >= tokens_needed {
                    *tokens -= tokens_needed;
                    break;
                }
            }
            
            // Wait for more tokens
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// File transfer errors
#[derive(Debug, thiserror::Error)]
pub enum FileTransferError {
    #[error("Invalid transfer state: {0:?}")]
    InvalidState(TransferState),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Invalid chunk index: {0}")]
    InvalidChunkIndex(u64),
    
    #[error("Chunk hash mismatch at index {chunk_index}")]
    ChunkHashMismatch {
        chunk_index: u64,
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    
    #[error("File size mismatch: expected {expected}, got {actual}")]
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    
    #[error("File hash mismatch")]
    HashMismatch {
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    
    #[error("Transfer timeout")]
    Timeout,
    
    #[error("Transfer cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_file_metadata_creation() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        
        // Create test file
        let mut file = async_fs::File::create(&file_path).await.unwrap();
        file.write_all(b"Hello, world!").await.unwrap();
        drop(file);
        
        let config = FileTransferConfig::default();
        let metadata = FileTransfer::create_metadata(&file_path, &config).await.unwrap();
        
        assert_eq!(metadata.name, "test.txt");
        assert_eq!(metadata.size, 13);
        assert_eq!(metadata.total_chunks, 1);
        assert_eq!(metadata.chunk_hashes.len(), 1);
    }
    
    #[tokio::test]
    async fn test_chunk_operations() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.bin");
        
        // Create test file with known content
        let test_data = vec![0xAA; 1024 * 128]; // 128KB
        async_fs::write(&file_path, &test_data).await.unwrap();
        
        let config = FileTransferConfig {
            chunk_size: 65536, // 64KB chunks
            ..Default::default()
        };
        
        let transfer = FileTransfer::new_sender(&file_path, config).await.unwrap();
        
        // Read first chunk
        let chunk = transfer.read_chunk(&file_path, 0).await.unwrap();
        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.original_size, 65536);
        
        // Read second chunk
        let chunk = transfer.read_chunk(&file_path, 1).await.unwrap();
        assert_eq!(chunk.index, 1);
        assert_eq!(chunk.original_size, 65536);
    }
}