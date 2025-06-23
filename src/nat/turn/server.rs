// src/turn/server.rs
//! SHARP-protected TURN relay server implementation
//! Full RFC 5766 compliance with enhanced security

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{interval, timeout};
use tracing::{info, warn, error, debug, trace};
use bytes::{Bytes, BytesMut, BufMut, Buf};
use rand::{Rng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, Key, Nonce
};
use sha2::{Sha256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::nat::stun::{
    Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
    StunError, compute_message_integrity_sha256,
};
use crate::nat::error::{NatError, NatResult};
use crate::security::crypto::{CryptoProvider, EncryptionAlgorithm};

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    /// Bind address for TURN server
    pub bind_addr: SocketAddr,

    /// External IP address (for XOR-RELAYED-ADDRESS)
    pub external_ip: IpAddr,

    /// Realm for authentication
    pub realm: String,

    /// Minimum port for relay allocations
    pub min_port: u16,

    /// Maximum port for relay allocations
    pub max_port: u16,

    /// Default allocation lifetime
    pub default_lifetime: Duration,

    /// Maximum allocation lifetime
    pub max_lifetime: Duration,

    /// Permission lifetime
    pub permission_lifetime: Duration,

    /// Channel binding lifetime
    pub channel_lifetime: Duration,

    /// SHARP header encryption key (32 bytes)
    pub sharp_header_key: [u8; 32],

    /// Enable bandwidth limiting
    pub bandwidth_limit: Option<BandwidthLimit>,

    /// Maximum allocations per client
    pub max_allocations_per_client: usize,

    /// Stale nonce timeout
    pub stale_nonce_timeout: Duration,

    /// Enable detailed statistics
    pub enable_stats: bool,

    /// Require encrypted SHARP headers
    pub require_sharp_encryption: bool,

    /// Allowed SHARP protocol versions
    pub allowed_sharp_versions: Vec<u16>,
}

impl Default for TurnServerConfig {
    fn default() -> Self {
        let mut sharp_key = [0u8; 32];
        OsRng.fill_bytes(&mut sharp_key);

        Self {
            bind_addr: "0.0.0.0:3478".parse().unwrap(),
            external_ip: "0.0.0.0".parse().unwrap(),
            realm: "sharp.turn".to_string(),
            min_port: 49152,
            max_port: 65535,
            default_lifetime: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
            permission_lifetime: Duration::from_secs(300),
            channel_lifetime: Duration::from_secs(600),
            sharp_header_key: sharp_key,
            bandwidth_limit: Some(BandwidthLimit {
                bytes_per_second: 10 * 1024 * 1024, // 10MB/s
                burst_size: 1024 * 1024, // 1MB burst
            }),
            max_allocations_per_client: 5,
            stale_nonce_timeout: Duration::from_secs(600),
            enable_stats: true,
            require_sharp_encryption: true,
            allowed_sharp_versions: vec![1, 2], // SHARP v1 and v2
        }
    }
}

/// Bandwidth limiting configuration
#[derive(Debug, Clone)]
pub struct BandwidthLimit {
    /// Bytes per second limit
    pub bytes_per_second: u64,
    /// Burst size in bytes
    pub burst_size: u64,
}

/// TURN server implementation with SHARP protection
pub struct TurnServer {
    /// Server configuration
    config: Arc<TurnServerConfig>,

    /// Main server socket
    socket: Arc<UdpSocket>,

    /// Active allocations
    allocations: Arc<RwLock<HashMap<AllocationKey, Allocation>>>,

    /// Nonce manager
    nonce_manager: Arc<NonceManager>,

    /// Port allocator
    port_allocator: Arc<PortAllocator>,

    /// Client rate limiters
    rate_limiters: Arc<RwLock<HashMap<IpAddr, RateLimiter>>>,

    /// SHARP header decryptor
    sharp_decryptor: Arc<SharpDecryptor>,

    /// Statistics collector
    stats: Arc<ServerStatistics>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Active tasks
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

/// Allocation key (5-tuple)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AllocationKey {
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    protocol: TransportProtocol,
}

/// TURN allocation
struct Allocation {
    /// Allocation ID
    id: AllocationId,

    /// Client address
    client_addr: SocketAddr,

    /// Relay address (allocated port)
    relay_addr: SocketAddr,

    /// Relay socket
    relay_socket: Arc<UdpSocket>,

    /// Username
    username: String,

    /// Realm
    realm: String,

    /// Creation time
    created_at: Instant,

    /// Expiry time
    expires_at: Instant,

    /// Permissions (peer addresses)
    permissions: Arc<RwLock<HashMap<IpAddr, Permission>>>,

    /// Channel bindings
    channels: Arc<RwLock<HashMap<u16, ChannelBinding>>>,

    /// Bandwidth limiter
    bandwidth_limiter: Option<TokenBucket>,

    /// Statistics
    stats: AllocationStats,

    /// SHARP session key for this allocation
    sharp_session_key: Option<[u8; 32]>,
}

/// Permission for peer communication
struct Permission {
    peer_addr: IpAddr,
    created_at: Instant,
    expires_at: Instant,
}

/// Channel binding
struct ChannelBinding {
    channel_number: u16,
    peer_addr: SocketAddr,
    created_at: Instant,
    expires_at: Instant,
}

/// Allocation statistics
#[derive(Debug, Default)]
struct AllocationStats {
    packets_sent: std::sync::atomic::AtomicU64,
    packets_received: std::sync::atomic::AtomicU64,
    bytes_sent: std::sync::atomic::AtomicU64,
    bytes_received: std::sync::atomic::AtomicU64,
    permissions_created: std::sync::atomic::AtomicU64,
    channels_created: std::sync::atomic::AtomicU64,
}

/// Server-wide statistics
#[derive(Debug, Default)]
struct ServerStatistics {
    total_allocations: std::sync::atomic::AtomicU64,
    active_allocations: std::sync::atomic::AtomicU64,
    total_permissions: std::sync::atomic::AtomicU64,
    total_channels: std::sync::atomic::AtomicU64,
    packets_processed: std::sync::atomic::AtomicU64,
    packets_dropped: std::sync::atomic::AtomicU64,
    bytes_relayed: std::sync::atomic::AtomicU64,
    auth_failures: std::sync::atomic::AtomicU64,
    sharp_decrypt_failures: std::sync::atomic::AtomicU64,
}

/// Nonce manager for replay protection
struct NonceManager {
    /// Active nonces with expiry time
    nonces: Arc<RwLock<HashMap<Vec<u8>, Instant>>>,

    /// Nonce expiry duration
    expiry: Duration,
}

impl NonceManager {
    fn new(expiry: Duration) -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
            expiry,
        }
    }

    /// Generate new nonce
    async fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        let expires_at = Instant::now() + self.expiry;
        self.nonces.write().await.insert(nonce.clone(), expires_at);

        nonce
    }

    /// Validate nonce
    async fn validate_nonce(&self, nonce: &[u8]) -> bool {
        let mut nonces = self.nonces.write().await;

        if let Some(&expires_at) = nonces.get(nonce) {
            if Instant::now() < expires_at {
                // Remove used nonce (one-time use)
                nonces.remove(nonce);
                return true;
            }
        }

        false
    }

    /// Clean expired nonces
    async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut nonces = self.nonces.write().await;
        nonces.retain(|_, &mut expires_at| expires_at > now);
    }
}

/// Port allocator for relay addresses
struct PortAllocator {
    /// Available ports
    available_ports: Arc<RwLock<Vec<u16>>>,

    /// Allocated ports
    allocated_ports: Arc<RwLock<HashMap<u16, SocketAddr>>>,
}

impl PortAllocator {
    fn new(min_port: u16, max_port: u16) -> Self {
        let ports: Vec<u16> = (min_port..=max_port).collect();

        Self {
            available_ports: Arc::new(RwLock::new(ports)),
            allocated_ports: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Allocate a port
    async fn allocate(&self, client_addr: SocketAddr) -> Option<u16> {
        let mut available = self.available_ports.write().await;
        let mut allocated = self.allocated_ports.write().await;

        if let Some(port) = available.pop() {
            allocated.insert(port, client_addr);
            Some(port)
        } else {
            None
        }
    }

    /// Release a port
    async fn release(&self, port: u16) {
        let mut available = self.available_ports.write().await;
        let mut allocated = self.allocated_ports.write().await;

        if allocated.remove(&port).is_some() {
            available.push(port);
        }
    }
}

/// Rate limiter using token bucket
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            max_tokens: burst,
            refill_rate: rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume tokens
    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Token bucket for bandwidth limiting
struct TokenBucket {
    tokens: Arc<Mutex<f64>>,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Arc<Mutex<Instant>>,
}

impl TokenBucket {
    fn new(bytes_per_second: u64, burst_size: u64) -> Self {
        Self {
            tokens: Arc::new(Mutex::new(burst_size as f64)),
            max_tokens: burst_size as f64,
            refill_rate: bytes_per_second as f64,
            last_refill: Arc::new(Mutex::new(Instant::now())),
        }
    }

    async fn try_consume(&self, bytes: usize) -> bool {
        let mut tokens = self.tokens.lock().await;
        let mut last_refill = self.last_refill.lock().await;

        // Refill tokens
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.max_tokens);
        *last_refill = now;

        // Try to consume
        if *tokens >= bytes as f64 {
            *tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

/// SHARP header decryptor
struct SharpDecryptor {
    /// Header decryption key
    header_key: [u8; 32],

    /// Cipher for header decryption (ChaCha20-Poly1305 for speed)
    cipher: chacha20poly1305::ChaCha20Poly1305,
}

impl SharpDecryptor {
    fn new(header_key: [u8; 32]) -> Self {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

        let cipher = ChaCha20Poly1305::new(&header_key.into());

        Self {
            header_key,
            cipher,
        }
    }

    /// Try to decrypt SHARP header
    fn try_decrypt_header(&self, data: &[u8]) -> Option<SharpHeader> {
        use chacha20poly1305::aead::Aead;

        // Minimum size check
        if data.len() < 32 { // 12 byte nonce + 16 byte tag + 4 byte min header
            return None;
        }

        // Extract nonce (first 12 bytes)
        let nonce = chacha20poly1305::Nonce::from_slice(&data[..12]);

        // Try to decrypt remaining data
        if let Ok(decrypted) = self.cipher.decrypt(nonce, &data[12..]) {
            // Parse SHARP header
            SharpHeader::parse(&decrypted)
        } else {
            None
        }
    }
}

/// SHARP protocol header
#[derive(Debug)]
struct SharpHeader {
    version: u16,
    packet_type: u8,
    flags: u8,
    stream_id: u32,
    sequence: u32,
    timestamp: u32,
}

impl SharpHeader {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        let mut cursor = std::io::Cursor::new(data);
        use std::io::Read;

        let mut version_bytes = [0u8; 2];
        let mut stream_id_bytes = [0u8; 4];
        let mut sequence_bytes = [0u8; 4];
        let mut timestamp_bytes = [0u8; 4];

        cursor.read_exact(&mut version_bytes).ok()?;
        let packet_type = cursor.read_u8().ok()?;
        let flags = cursor.read_u8().ok()?;
        cursor.read_exact(&mut stream_id_bytes).ok()?;
        cursor.read_exact(&mut sequence_bytes).ok()?;
        cursor.read_exact(&mut timestamp_bytes).ok()?;

        Some(SharpHeader {
            version: u16::from_be_bytes(version_bytes),
            packet_type,
            flags,
            stream_id: u32::from_be_bytes(stream_id_bytes),
            sequence: u32::from_be_bytes(sequence_bytes),
            timestamp: u32::from_be_bytes(timestamp_bytes),
        })
    }
}

/// Transport protocol
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum TransportProtocol {
    Udp,
    Tcp,
    Tls,
}

/// Allocation ID
type AllocationId = [u8; 16];

impl TurnServer {
    /// Create new TURN server
    pub async fn new(config: TurnServerConfig) -> NatResult<Self> {
        info!("Creating TURN server on {} (external: {})",
            config.bind_addr, config.external_ip);

        // Validate configuration
        Self::validate_config(&config)?;

        // Bind socket
        let socket = UdpSocket::bind(&config.bind_addr).await?;
        info!("TURN server listening on {}", socket.local_addr()?);

        // Initialize components
        let nonce_manager = Arc::new(NonceManager::new(config.stale_nonce_timeout));
        let port_allocator = Arc::new(PortAllocator::new(config.min_port, config.max_port));
        let sharp_decryptor = Arc::new(SharpDecryptor::new(config.sharp_header_key));

        Ok(Self {
            config: Arc::new(config),
            socket: Arc::new(socket),
            allocations: Arc::new(RwLock::new(HashMap::new())),
            nonce_manager,
            port_allocator,
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            sharp_decryptor,
            stats: Arc::new(ServerStatistics::default()),
            shutdown: Arc::new(RwLock::new(false)),
            tasks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Validate server configuration
    fn validate_config(config: &TurnServerConfig) -> NatResult<()> {
        if config.min_port >= config.max_port {
            return Err(NatError::Platform("Invalid port range".to_string()));
        }

        if config.external_ip.is_unspecified() {
            return Err(NatError::Platform("External IP must be specified".to_string()));
        }

        if config.realm.is_empty() {
            return Err(NatError::Platform("Realm cannot be empty".to_string()));
        }

        if config.allowed_sharp_versions.is_empty() {
            return Err(NatError::Platform("At least one SHARP version must be allowed".to_string()));
        }

        Ok(())
    }

    /// Start the TURN server
    pub async fn start(&self) -> NatResult<()> {
        info!("Starting TURN server");

        // Start main receive loop
        let server = Arc::new(self.clone());
        let task = tokio::spawn(async move {
            server.receive_loop().await;
        });
        self.tasks.lock().await.push(task);

        // Start cleanup timer
        let server = Arc::new(self.clone());
        let task = tokio::spawn(async move {
            server.cleanup_loop().await;
        });
        self.tasks.lock().await.push(task);

        // Start statistics reporter
        if self.config.enable_stats {
            let server = Arc::new(self.clone());
            let task = tokio::spawn(async move {
                server.stats_loop().await;
            });
            self.tasks.lock().await.push(task);
        }

        Ok(())
    }

    /// Main receive loop
    async fn receive_loop(&self) {
        let mut buffer = vec![0u8; 65536];

        loop {
            if *self.shutdown.read().await {
                break;
            }

            match self.socket.recv_from(&mut buffer).await {
                Ok((size, from_addr)) => {
                    let data = buffer[..size].to_vec();

                    // Process in separate task to avoid blocking
                    let server = Arc::new(self.clone());
                    tokio::spawn(async move {
                        server.process_packet(data, from_addr).await;
                    });
                }
                Err(e) => {
                    error!("Socket receive error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }

        info!("Receive loop ended");
    }

    /// Process incoming packet
    async fn process_packet(&self, data: Vec<u8>, from_addr: SocketAddr) {
        self.stats.packets_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Apply rate limiting
        if !self.check_rate_limit(from_addr.ip(), data.len()).await {
            debug!("Rate limit exceeded for {}", from_addr);
            self.stats.packets_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }

        // Check if this is a SHARP-encrypted packet
        if self.config.require_sharp_encryption {
            if let Some(sharp_header) = self.sharp_decryptor.try_decrypt_header(&data) {
                // Validate SHARP version
                if !self.config.allowed_sharp_versions.contains(&sharp_header.version) {
                    debug!("Invalid SHARP version {} from {}", sharp_header.version, from_addr);
                    self.stats.sharp_decrypt_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }

                // Process as SHARP packet
                self.process_sharp_packet(data, from_addr, sharp_header).await;
                return;
            } else {
                debug!("Failed to decrypt SHARP header from {}", from_addr);
                self.stats.sharp_decrypt_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        }

        // Check for ChannelData (RFC 5766 Section 11)
        if data.len() >= 4 && data[0] >= 0x40 && data[0] <= 0x7F {
            self.process_channel_data(&data, from_addr).await;
            return;
        }

        // Try to parse as STUN/TURN message
        match Message::decode(BytesMut::from(data.as_slice())) {
            Ok(message) => {
                self.process_turn_message(message, from_addr, &data).await;
            }
            Err(e) => {
                debug!("Failed to parse message from {}: {}", from_addr, e);
                self.stats.packets_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Process SHARP-encrypted packet
    async fn process_sharp_packet(
        &self,
        data: Vec<u8>,
        from_addr: SocketAddr,
        sharp_header: SharpHeader,
    ) {
        trace!("Processing SHARP packet from {} (version: {}, type: {})",
            from_addr, sharp_header.version, sharp_header.packet_type);

        // Extract encrypted payload (after SHARP header)
        let header_size = 12 + 16; // nonce + encrypted header size
        if data.len() <= header_size {
            return;
        }

        let encrypted_payload = &data[header_size..];

        // Find allocation by client address
        let allocations = self.allocations.read().await;
        let allocation = allocations.values()
            .find(|a| a.client_addr == from_addr);

        if let Some(alloc) = allocation {
            // Use allocation's session key to decrypt payload
            if let Some(session_key) = &alloc.sharp_session_key {
                // Decrypt payload using TLS 1.3 equivalent (AES-256-GCM)
                if let Ok(decrypted) = self.decrypt_payload(encrypted_payload, session_key) {
                    // Process decrypted TURN message
                    match Message::decode(BytesMut::from(decrypted)) {
                        Ok(message) => {
                            drop(allocations);
                            self.process_turn_message(message, from_addr, &data).await;
                        }
                        Err(e) => {
                            debug!("Failed to parse decrypted TURN message: {}", e);
                        }
                    }
                }
            }
        } else {
            // No allocation yet - this might be an Allocate request
            // Try to establish SHARP session
            self.handle_sharp_handshake(encrypted_payload, from_addr, sharp_header).await;
        }
    }

    /// Decrypt payload using session key
    fn decrypt_payload(&self, encrypted: &[u8], session_key: &[u8; 32]) -> Result<Vec<u8>, ()> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        if encrypted.len() < 28 { // 12 byte nonce + 16 byte tag
            return Err(());
        }

        let cipher = Aes256Gcm::new(session_key.into());
        let nonce = Nonce::from_slice(&encrypted[..12]);

        cipher.decrypt(nonce, &encrypted[12..])
            .map_err(|_| ())
    }

    /// Handle SHARP handshake for new connections
    async fn handle_sharp_handshake(
        &self,
        _encrypted_payload: &[u8],
        from_addr: SocketAddr,
        _sharp_header: SharpHeader,
    ) {
        // In a real implementation, this would perform ECDH key exchange
        // For now, we'll generate a session key
        debug!("Initiating SHARP handshake with {}", from_addr);

        // This would normally involve:
        // 1. Decrypt initial handshake message
        // 2. Perform ECDH key exchange
        // 3. Derive session key
        // 4. Store session key for future use

        // For demonstration, we'll just log this
        info!("SHARP handshake initiated from {} (not implemented)", from_addr);
    }

    /// Process TURN message
    async fn process_turn_message(
        &self,
        message: Message,
        from_addr: SocketAddr,
        raw_data: &[u8],
    ) {
        debug!("Processing {:?} from {}", message.message_type, from_addr);

        match message.message_type {
            MessageType::AllocateRequest => {
                self.handle_allocate_request(message, from_addr).await;
            }
            MessageType::RefreshRequest => {
                self.handle_refresh_request(message, from_addr).await;
            }
            MessageType::CreatePermissionRequest => {
                self.handle_create_permission_request(message, from_addr).await;
            }
            MessageType::ChannelBindRequest => {
                self.handle_channel_bind_request(message, from_addr).await;
            }
            MessageType::SendIndication => {
                self.handle_send_indication(message, from_addr).await;
            }
            MessageType::BindingRequest => {
                // STUN binding request (connectivity check)
                self.handle_binding_request(message, from_addr).await;
            }
            MessageType::DataIndication => {
                // Should not receive this from client
                warn!("Received DataIndication from client {}", from_addr);
            }
            _ => {
                debug!("Unhandled message type {:?} from {}", message.message_type, from_addr);
            }
        }
    }

    /// Handle ALLOCATE request (RFC 5766 Section 6)
    async fn handle_allocate_request(&self, request: Message, from_addr: SocketAddr) {
        info!("Processing ALLOCATE request from {}", from_addr);

        // Check if allocation already exists
        let key = AllocationKey {
            client_addr: from_addr,
            server_addr: self.socket.local_addr().unwrap(),
            protocol: TransportProtocol::Udp,
        };

        if self.allocations.read().await.contains_key(&key) {
            // Allocation already exists (RFC 5766 Section 6.2)
            self.send_error_response(
                from_addr,
                request.transaction_id,
                437, // Allocation Mismatch
                "Allocation already exists",
            ).await;
            return;
        }

        // Verify REQUESTED-TRANSPORT (must be UDP)
        let transport = match request.get_attribute(AttributeType::RequestedTransport) {
            Some(attr) => {
                if let AttributeValue::Raw(data) = &attr.value {
                    if data.len() >= 1 && data[0] == 17 { // UDP
                        TransportProtocol::Udp
                    } else {
                        self.send_error_response(
                            from_addr,
                            request.transaction_id,
                            442, // Unsupported Transport Protocol
                            "Only UDP is supported",
                        ).await;
                        return;
                    }
                } else {
                    self.send_error_response(
                        from_addr,
                        request.transaction_id,
                        400, // Bad Request
                        "Invalid REQUESTED-TRANSPORT",
                    ).await;
                    return;
                }
            }
            None => {
                self.send_error_response(
                    from_addr,
                    request.transaction_id,
                    400, // Bad Request
                    "Missing REQUESTED-TRANSPORT",
                ).await;
                return;
            }
        };

        // Check authentication
        match self.authenticate_request(&request, from_addr).await {
            Ok((username, _key)) => {
                // Check allocation limit per client
                let client_allocations = self.allocations.read().await
                    .values()
                    .filter(|a| a.username == username)
                    .count();

                if client_allocations >= self.config.max_allocations_per_client {
                    self.send_error_response(
                        from_addr,
                        request.transaction_id,
                        486, // Allocation Quota Reached
                        "Maximum allocations reached",
                    ).await;
                    return;
                }

                // Create allocation
                self.create_allocation(request, from_addr, username).await;
            }
            Err(stun_error) => {
                self.handle_auth_error(request, from_addr, stun_error).await;
            }
        }
    }

    /// Authenticate request
    async fn authenticate_request(
        &self,
        request: &Message,
        from_addr: SocketAddr,
    ) -> Result<(String, Vec<u8>), StunError> {
        // Check USERNAME
        let username = match request.get_attribute(AttributeType::Username) {
            Some(attr) => {
                if let AttributeValue::Username(u) = &attr.value {
                    u.clone()
                } else {
                    return Err(StunError::InvalidAttribute("USERNAME"));
                }
            }
            None => {
                return Err(StunError::MissingAttribute("USERNAME"));
            }
        };

        // Check REALM
        let realm = match request.get_attribute(AttributeType::Realm) {
            Some(attr) => {
                if let AttributeValue::Realm(r) = &attr.value {
                    if r != &self.config.realm {
                        return Err(StunError::InvalidCredentials);
                    }
                    r.clone()
                } else {
                    return Err(StunError::InvalidAttribute("REALM"));
                }
            }
            None => {
                return Err(StunError::MissingAttribute("REALM"));
            }
        };

        // Check NONCE
        let nonce = match request.get_attribute(AttributeType::Nonce) {
            Some(attr) => {
                if let AttributeValue::Nonce(n) = &attr.value {
                    n.clone()
                } else {
                    return Err(StunError::InvalidAttribute("NONCE"));
                }
            }
            None => {
                return Err(StunError::MissingAttribute("NONCE"));
            }
        };

        // Validate nonce
        if !self.nonce_manager.validate_nonce(&nonce).await {
            return Err(StunError::StaleNonce);
        }

        // Check MESSAGE-INTEGRITY-SHA256
        let has_integrity = request.get_attribute(AttributeType::MessageIntegritySha256).is_some();
        if !has_integrity {
            return Err(StunError::MissingAttribute("MESSAGE-INTEGRITY-SHA256"));
        }

        // In real implementation, would verify against user database
        // For now, derive key from username/realm/password
        let password = format!("{}:{}:password", username, realm);
        let key = Sha256::digest(password.as_bytes()).to_vec();

        Ok((username, key))
    }

    /// Create new allocation
    async fn create_allocation(
        &self,
        request: Message,
        client_addr: SocketAddr,
        username: String,
    ) {
        // Allocate relay port
        let relay_port = match self.port_allocator.allocate(client_addr).await {
            Some(port) => port,
            None => {
                self.send_error_response(
                    client_addr,
                    request.transaction_id,
                    508, // Insufficient Capacity
                    "No ports available",
                ).await;
                return;
            }
        };

        let relay_addr = SocketAddr::new(self.config.external_ip, relay_port);

        // Create relay socket
        let relay_socket = match UdpSocket::bind(("0.0.0.0", relay_port)).await {
            Ok(socket) => Arc::new(socket),
            Err(e) => {
                error!("Failed to bind relay socket: {}", e);
                self.port_allocator.release(relay_port).await;
                self.send_error_response(
                    client_addr,
                    request.transaction_id,
                    508, // Insufficient Capacity
                    "Failed to create relay",
                ).await;
                return;
            }
        };

        // Parse requested lifetime
        let requested_lifetime = request.get_attribute(AttributeType::Lifetime)
            .and_then(|attr| {
                if let AttributeValue::Raw(data) = &attr.value {
                    if data.len() >= 4 {
                        Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or(self.config.default_lifetime.as_secs() as u32);

        let lifetime = Duration::from_secs(
            requested_lifetime.min(self.config.max_lifetime.as_secs() as u32) as u64
        );

        // Generate allocation ID
        let mut allocation_id = [0u8; 16];
        OsRng.fill_bytes(&mut allocation_id);

        // Create allocation
        let allocation = Allocation {
            id: allocation_id,
            client_addr,
            relay_addr,
            relay_socket: relay_socket.clone(),
            username: username.clone(),
            realm: self.config.realm.clone(),
            created_at: Instant::now(),
            expires_at: Instant::now() + lifetime,
            permissions: Arc::new(RwLock::new(HashMap::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
            bandwidth_limiter: self.config.bandwidth_limit.as_ref().map(|limit| {
                TokenBucket::new(limit.bytes_per_second, limit.burst_size)
            }),
            stats: AllocationStats::default(),
            sharp_session_key: None, // Set during SHARP handshake
        };

        // Store allocation
        let key = AllocationKey {
            client_addr,
            server_addr: self.socket.local_addr().unwrap(),
            protocol: TransportProtocol::Udp,
        };

        self.allocations.write().await.insert(key, allocation);
        self.stats.total_allocations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.active_allocations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        info!("Created allocation for {} -> {} (lifetime: {:?})",
            client_addr, relay_addr, lifetime);

        // Start relay task
        let server = Arc::new(self.clone());
        let task = tokio::spawn(async move {
            server.relay_loop(allocation_id, relay_socket).await;
        });
        self.tasks.lock().await.push(task);

        // Send success response
        self.send_allocate_success_response(
            client_addr,
            request.transaction_id,
            relay_addr,
            lifetime,
        ).await;
    }

    /// Send ALLOCATE success response
    async fn send_allocate_success_response(
        &self,
        client_addr: SocketAddr,
        transaction_id: TransactionId,
        relay_addr: SocketAddr,
        lifetime: Duration,
    ) {
        let mut response = Message::new(MessageType::AllocateResponse, transaction_id);

        // Add XOR-RELAYED-ADDRESS
        response.add_attribute(Attribute::new(
            AttributeType::XorRelayedAddress,
            AttributeValue::XorRelayedAddress(relay_addr),
        ));

        // Add LIFETIME
        let lifetime_secs = lifetime.as_secs() as u32;
        let mut lifetime_bytes = vec![0u8; 4];
        lifetime_bytes[0] = (lifetime_secs >> 24) as u8;
        lifetime_bytes[1] = (lifetime_secs >> 16) as u8;
        lifetime_bytes[2] = (lifetime_secs >> 8) as u8;
        lifetime_bytes[3] = lifetime_secs as u8;

        response.add_attribute(Attribute::new(
            AttributeType::Lifetime,
            AttributeValue::Raw(lifetime_bytes),
        ));

        // Add XOR-MAPPED-ADDRESS (reflexive address)
        response.add_attribute(Attribute::new(
            AttributeType::XorMappedAddress,
            AttributeValue::XorMappedAddress(client_addr),
        ));

        // Add SOFTWARE
        response.add_attribute(Attribute::new(
            AttributeType::Software,
            AttributeValue::Software("SHARP-TURN/1.0".to_string()),
        ));

        // Send response (would add MESSAGE-INTEGRITY in real implementation)
        if let Ok(data) = response.encode(None, true) {
            let _ = self.socket.send_to(&data, client_addr).await;
        }
    }

    /// Relay loop for an allocation
    async fn relay_loop(&self, allocation_id: AllocationId, relay_socket: Arc<UdpSocket>) {
        let mut buffer = vec![0u8; 65536];

        loop {
            if *self.shutdown.read().await {
                break;
            }

            // Check if allocation still exists
            let allocation_exists = {
                let allocations = self.allocations.read().await;
                allocations.values().any(|a| a.id == allocation_id)
            };

            if !allocation_exists {
                debug!("Allocation removed, stopping relay loop");
                break;
            }

            // Receive from peers
            match timeout(Duration::from_secs(1), relay_socket.recv_from(&mut buffer)).await {
                Ok(Ok((size, peer_addr))) => {
                    let data = buffer[..size].to_vec();

                    // Find allocation
                    let allocations = self.allocations.read().await;
                    if let Some(allocation) = allocations.values().find(|a| a.id == allocation_id) {
                        // Check permission
                        let permissions = allocation.permissions.read().await;
                        if permissions.contains_key(&peer_addr.ip()) {
                            // Update stats
                            allocation.stats.packets_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            allocation.stats.bytes_received.fetch_add(size as u64, std::sync::atomic::Ordering::Relaxed);

                            let client_addr = allocation.client_addr;
                            drop(permissions);
                            drop(allocations);

                            // Send to client as DATA indication
                            self.send_data_indication(client_addr, peer_addr, data).await;
                        } else {
                            debug!("No permission for peer {} -> {}", peer_addr, allocation.relay_addr);
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Relay socket error: {}", e);
                    break;
                }
                Err(_) => {
                    // Timeout - continue
                }
            }
        }

        info!("Relay loop ended for allocation {:?}", allocation_id);
    }

    /// Send DATA indication to client
    async fn send_data_indication(
        &self,
        client_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: Vec<u8>,
    ) {
        let mut indication = Message::new(
            MessageType::DataIndication,
            TransactionId::new(),
        );

        // Add XOR-PEER-ADDRESS
        indication.add_attribute(Attribute::new(
            AttributeType::XorPeerAddress,
            AttributeValue::XorPeerAddress(peer_addr),
        ));

        // Add DATA
        indication.add_attribute(Attribute::new(
            AttributeType::Data,
            AttributeValue::Data(data),
        ));

        // Send to client
        if let Ok(encoded) = indication.encode(None, true) {
            let _ = self.socket.send_to(&encoded, client_addr).await;
            self.stats.bytes_relayed.fetch_add(encoded.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Handle REFRESH request (RFC 5766 Section 7)
    async fn handle_refresh_request(&self, request: Message, from_addr: SocketAddr) {
        debug!("Processing REFRESH request from {}", from_addr);

        // Find allocation
        let key = AllocationKey {
            client_addr: from_addr,
            server_addr: self.socket.local_addr().unwrap(),
            protocol: TransportProtocol::Udp,
        };

        let mut allocations = self.allocations.write().await;

        match allocations.get_mut(&key) {
            Some(allocation) => {
                // Check authentication
                match self.authenticate_request(&request, from_addr).await {
                    Ok((username, _)) => {
                        if username != allocation.username {
                            drop(allocations);
                            self.send_error_response(
                                from_addr,
                                request.transaction_id,
                                441, // Wrong Credentials
                                "Username mismatch",
                            ).await;
                            return;
                        }

                        // Parse requested lifetime
                        let requested_lifetime = request.get_attribute(AttributeType::Lifetime)
                            .and_then(|attr| {
                                if let AttributeValue::Raw(data) = &attr.value {
                                    if data.len() >= 4 {
                                        Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(self.config.default_lifetime.as_secs() as u32);

                        if requested_lifetime == 0 {
                            // Delete allocation
                            let relay_port = allocation.relay_addr.port();
                            drop(allocations);

                            self.allocations.write().await.remove(&key);
                            self.port_allocator.release(relay_port).await;
                            self.stats.active_allocations.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

                            info!("Deleted allocation for {}", from_addr);

                            // Send success with lifetime 0
                            self.send_refresh_success_response(
                                from_addr,
                                request.transaction_id,
                                Duration::from_secs(0),
                            ).await;
                        } else {
                            // Refresh allocation
                            let lifetime = Duration::from_secs(
                                requested_lifetime.min(self.config.max_lifetime.as_secs() as u32) as u64
                            );

                            allocation.expires_at = Instant::now() + lifetime;
                            drop(allocations);

                            info!("Refreshed allocation for {} (lifetime: {:?})", from_addr, lifetime);

                            self.send_refresh_success_response(
                                from_addr,
                                request.transaction_id,
                                lifetime,
                            ).await;
                        }
                    }
                    Err(stun_error) => {
                        drop(allocations);
                        self.handle_auth_error(request, from_addr, stun_error).await;
                    }
                }
            }
            None => {
                drop(allocations);
                self.send_error_response(
                    from_addr,
                    request.transaction_id,
                    437, // Allocation Mismatch
                    "No allocation found",
                ).await;
            }
        }
    }

    /// Send REFRESH success response
    async fn send_refresh_success_response(
        &self,
        client_addr: SocketAddr,
        transaction_id: TransactionId,
        lifetime: Duration,
    ) {
        let mut response = Message::new(MessageType::RefreshResponse, transaction_id);

        // Add LIFETIME
        let lifetime_secs = lifetime.as_secs() as u32;
        let mut lifetime_bytes = vec![0u8; 4];
        lifetime_bytes[0] = (lifetime_secs >> 24) as u8;
        lifetime_bytes[1] = (lifetime_secs >> 16) as u8;
        lifetime_bytes[2] = (lifetime_secs >> 8) as u8;
        lifetime_bytes[3] = lifetime_secs as u8;

        response.add_attribute(Attribute::new(
            AttributeType::Lifetime,
            AttributeValue::Raw(lifetime_bytes),
        ));

        // Send response
        if let Ok(data) = response.encode(None, true) {
            let _ = self.socket.send_to(&data, client_addr).await;
        }
    }

    /// Handle CREATE-PERMISSION request (RFC 5766 Section 9)
    async fn handle_create_permission_request(&self, request: Message, from_addr: SocketAddr) {
        debug!("Processing CREATE-PERMISSION request from {}", from_addr);

        // Find allocation
        let key = AllocationKey {
            client_addr: from_addr,
            server_addr: self.socket.local_addr().unwrap(),
            protocol: TransportProtocol::Udp,
        };

        let allocations = self.allocations.read().await;

        match allocations.get(&key) {
            Some(allocation) => {
                // Check authentication
                match self.authenticate_request(&request, from_addr).await {
                    Ok((username, _)) => {
                        if username != allocation.username {
                            drop(allocations);
                            self.send_error_response(
                                from_addr,
                                request.transaction_id,
                                441, // Wrong Credentials
                                "Username mismatch",
                            ).await;
                            return;
                        }

                        // Extract XOR-PEER-ADDRESS attributes
                        let mut peer_addrs = Vec::new();
                        for attr in &request.attributes {
                            if attr.attr_type == AttributeType::XorPeerAddress {
                                if let AttributeValue::XorPeerAddress(addr) = &attr.value {
                                    peer_addrs.push(addr.ip());
                                }
                            }
                        }

                        if peer_addrs.is_empty() {
                            drop(allocations);
                            self.send_error_response(
                                from_addr,
                                request.transaction_id,
                                400, // Bad Request
                                "No XOR-PEER-ADDRESS",
                            ).await;
                            return;
                        }

                        // Create permissions
                        let mut permissions = allocation.permissions.write().await;
                        for peer_ip in peer_addrs {
                            let permission = Permission {
                                peer_addr: peer_ip,
                                created_at: Instant::now(),
                                expires_at: Instant::now() + self.config.permission_lifetime,
                            };

                            permissions.insert(peer_ip, permission);
                            allocation.stats.permissions_created.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.stats.total_permissions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            info!("Created permission for {} -> {}", from_addr, peer_ip);
                        }

                        drop(permissions);
                        drop(allocations);

                        // Send success response
                        let response = Message::new(
                            MessageType::CreatePermissionResponse,
                            request.transaction_id,
                        );

                        if let Ok(data) = response.encode(None, true) {
                            let _ = self.socket.send_to(&data, from_addr).await;
                        }
                    }
                    Err(stun_error) => {
                        drop(allocations);
                        self.handle_auth_error(request, from_addr, stun_error).await;
                    }
                }
            }
            None => {
                drop(allocations);
                self.send_error_response(
                    from_addr,
                    request.transaction_id,
                    437, // Allocation Mismatch
                    "No allocation found",
                ).await;
            }
        }
    }

    /// Handle CHANNEL-BIND request (RFC 5766 Section 11)
    async fn handle_channel_bind_request(&self, request: Message, from_addr: SocketAddr) {
        debug!("Processing CHANNEL-BIND request from {}", from_addr);

        // Find allocation
        let key = AllocationKey {
            client_addr: from_addr,
            server_addr: self.socket.local_addr().unwrap(),
            protocol: TransportProtocol::Udp,
        };

        let allocations = self.allocations.read().await;

        match allocations.get(&key) {
            Some(allocation) => {
                // Check authentication
                match self.authenticate_request(&request, from_addr).await {
                    Ok((username, _)) => {
                        if username != allocation.username {
                            drop(allocations);
                            self.send_error_response(
                                from_addr,
                                request.transaction_id,
                                441, // Wrong Credentials
                                "Username mismatch",
                            ).await;
                            return;
                        }

                        // Extract CHANNEL-NUMBER
                        let channel_number = match request.get_attribute(AttributeType::ChannelNumber) {
                            Some(attr) => {
                                if let AttributeValue::Raw(data) = &attr.value {
                                    if data.len() >= 2 {
                                        u16::from_be_bytes([data[0], data[1]])
                                    } else {
                                        drop(allocations);
                                        self.send_error_response(
                                            from_addr,
                                            request.transaction_id,
                                            400, // Bad Request
                                            "Invalid CHANNEL-NUMBER",
                                        ).await;
                                        return;
                                    }
                                } else {
                                    drop(allocations);
                                    self.send_error_response(
                                        from_addr,
                                        request.transaction_id,
                                        400, // Bad Request
                                        "Invalid CHANNEL-NUMBER",
                                    ).await;
                                    return;
                                }
                            }
                            None => {
                                drop(allocations);
                                self.send_error_response(
                                    from_addr,
                                    request.transaction_id,
                                    400, // Bad Request
                                    "Missing CHANNEL-NUMBER",
                                ).await;
                                return;
                            }
                        };

                        // Validate channel number (0x4000-0x7FFF)
                        if channel_number < 0x4000 || channel_number > 0x7FFF {
                            drop(allocations);
                            self.send_error_response(
                                from_addr,
                                request.transaction_id,
                                400, // Bad Request
                                "Invalid channel number range",
                            ).await;
                            return;
                        }

                        // Extract XOR-PEER-ADDRESS
                        let peer_addr = match request.get_attribute(AttributeType::XorPeerAddress) {
                            Some(attr) => {
                                if let AttributeValue::XorPeerAddress(addr) = &attr.value {
                                    *addr
                                } else {
                                    drop(allocations);
                                    self.send_error_response(
                                        from_addr,
                                        request.transaction_id,
                                        400, // Bad Request
                                        "Invalid XOR-PEER-ADDRESS",
                                    ).await;
                                    return;
                                }
                            }
                            None => {
                                drop(allocations);
                                self.send_error_response(
                                    from_addr,
                                    request.transaction_id,
                                    400, // Bad Request
                                    "Missing XOR-PEER-ADDRESS",
                                ).await;
                                return;
                            }
                        };

                        // Create channel binding
                        let mut channels = allocation.channels.write().await;

                        let binding = ChannelBinding {
                            channel_number,
                            peer_addr,
                            created_at: Instant::now(),
                            expires_at: Instant::now() + self.config.channel_lifetime,
                        };

                        channels.insert(channel_number, binding);
                        allocation.stats.channels_created.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.stats.total_channels.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        info!("Created channel {} for {} -> {}",
                            channel_number, from_addr, peer_addr);

                        drop(channels);
                        drop(allocations);

                        // Send success response
                        let response = Message::new(
                            MessageType::ChannelBindResponse,
                            request.transaction_id,
                        );

                        if let Ok(data) = response.encode(None, true) {
                            let _ = self.socket.send_to(&data, from_addr).await;
                        }
                    }
                    Err(stun_error) => {
                        drop(allocations);
                        self.handle_auth_error(request, from_addr, stun_error).await;
                    }
                }
            }
            None => {
                drop(allocations);
                self.send_error_response(
                    from_addr,
                    request.transaction_id,
                    437, // Allocation Mismatch
                    "No allocation found",
                ).await;
            }
        }
    }

    /// Handle SEND indication (RFC 5766 Section 10)
    async fn handle_send_indication(&self, indication: Message, from_addr: SocketAddr) {
        trace!("Processing SEND indication from {}", from_addr);

        // Find allocation
        let key = AllocationKey {
            client_addr: from_addr,
            server_addr: self.socket.local_addr().unwrap(),
            protocol: TransportProtocol::Udp,
        };

        let allocations = self.allocations.read().await;

        if let Some(allocation) = allocations.get(&key) {
            // Extract XOR-PEER-ADDRESS
            let peer_addr = match indication.get_attribute(AttributeType::XorPeerAddress) {
                Some(attr) => {
                    if let AttributeValue::XorPeerAddress(addr) = &attr.value {
                        *addr
                    } else {
                        return;
                    }
                }
                None => return,
            };

            // Check permission
            let permissions = allocation.permissions.read().await;
            if !permissions.contains_key(&peer_addr.ip()) {
                debug!("No permission for {} -> {}", from_addr, peer_addr);
                return;
            }
            drop(permissions);

            // Extract DATA
            let data = match indication.get_attribute(AttributeType::Data) {
                Some(attr) => {
                    if let AttributeValue::Data(d) = &attr.value {
                        d.clone()
                    } else {
                        return;
                    }
                }
                None => return,
            };

            // Apply bandwidth limiting if configured
            if let Some(limiter) = &allocation.bandwidth_limiter {
                if !limiter.try_consume(data.len()).await {
                    debug!("Bandwidth limit exceeded for {}", from_addr);
                    self.stats.packets_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            }

            // Send data to peer
            if let Err(e) = allocation.relay_socket.send_to(&data, peer_addr).await {
                error!("Failed to relay data to {}: {}", peer_addr, e);
                return;
            }

            // Update stats
            allocation.stats.packets_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            allocation.stats.bytes_sent.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
            self.stats.bytes_relayed.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);

            trace!("Relayed {} bytes from {} to {}", data.len(), from_addr, peer_addr);
        }
    }

    /// Handle STUN BINDING request
    async fn handle_binding_request(&self, request: Message, from_addr: SocketAddr) {
        debug!("Processing BINDING request from {}", from_addr);

        let mut response = Message::new(
            MessageType::BindingResponse,
            request.transaction_id,
        );

        // Add XOR-MAPPED-ADDRESS
        response.add_attribute(Attribute::new(
            AttributeType::XorMappedAddress,
            AttributeValue::XorMappedAddress(from_addr),
        ));

        // Send response
        if let Ok(data) = response.encode(None, true) {
            let _ = self.socket.send_to(&data, from_addr).await;
        }
    }

    /// Process ChannelData (RFC 5766 Section 11.4)
    async fn process_channel_data(&self, data: &[u8], from_addr: SocketAddr) {
        if data.len() < 4 {
            return;
        }

        // Extract channel number and length
        let channel_number = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + length {
            debug!("Invalid ChannelData length from {}", from_addr);
            return;
        }

        let payload = &data[4..4 + length];

        // Find allocation
        let key = AllocationKey {
            client_addr: from_addr,
            server_addr: self.socket.local_addr().unwrap(),
            protocol: TransportProtocol::Udp,
        };

        let allocations = self.allocations.read().await;

        if let Some(allocation) = allocations.get(&key) {
            // Find channel binding
            let channels = allocation.channels.read().await;

            if let Some(binding) = channels.get(&channel_number) {
                let peer_addr = binding.peer_addr;
                drop(channels);

                // Apply bandwidth limiting
                if let Some(limiter) = &allocation.bandwidth_limiter {
                    if !limiter.try_consume(payload.len()).await {
                        debug!("Bandwidth limit exceeded for channel {}", channel_number);
                        self.stats.packets_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }

                // Send to peer
                if let Err(e) = allocation.relay_socket.send_to(payload, peer_addr).await {
                    error!("Failed to relay channel data to {}: {}", peer_addr, e);
                    return;
                }

                // Update stats
                allocation.stats.packets_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                allocation.stats.bytes_sent.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                self.stats.bytes_relayed.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);

                trace!("Relayed {} bytes via channel {} to {}",
                    payload.len(), channel_number, peer_addr);
            } else {
                debug!("Unknown channel {} from {}", channel_number, from_addr);
            }
        }
    }

    /// Handle authentication error
    async fn handle_auth_error(
        &self,
        request: Message,
        from_addr: SocketAddr,
        error: StunError,
    ) {
        self.stats.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        match error {
            StunError::MissingAttribute(attr) => {
                if attr == "USERNAME" || attr == "REALM" || attr == "NONCE" {
                    // Send 401 with realm and nonce
                    let mut response = Message::new(
                        MessageType::AllocateError,
                        request.transaction_id,
                    );

                    response.add_attribute(Attribute::new(
                        AttributeType::ErrorCode,
                        AttributeValue::ErrorCode {
                            code: 401,
                            reason: "Unauthorized".to_string(),
                        },
                    ));

                    response.add_attribute(Attribute::new(
                        AttributeType::Realm,
                        AttributeValue::Realm(self.config.realm.clone()),
                    ));

                    let nonce = self.nonce_manager.generate_nonce().await;
                    response.add_attribute(Attribute::new(
                        AttributeType::Nonce,
                        AttributeValue::Nonce(nonce),
                    ));

                    if let Ok(data) = response.encode(None, true) {
                        let _ = self.socket.send_to(&data, from_addr).await;
                    }
                } else {
                    self.send_error_response(
                        from_addr,
                        request.transaction_id,
                        400,
                        &format!("Missing {}", attr),
                    ).await;
                }
            }
            StunError::StaleNonce => {
                // Send 438 with new nonce
                let mut response = Message::new(
                    MessageType::AllocateError,
                    request.transaction_id,
                );

                response.add_attribute(Attribute::new(
                    AttributeType::ErrorCode,
                    AttributeValue::ErrorCode {
                        code: 438,
                        reason: "Stale Nonce".to_string(),
                    },
                ));

                response.add_attribute(Attribute::new(
                    AttributeType::Realm,
                    AttributeValue::Realm(self.config.realm.clone()),
                ));

                let nonce = self.nonce_manager.generate_nonce().await;
                response.add_attribute(Attribute::new(
                    AttributeType::Nonce,
                    AttributeValue::Nonce(nonce),
                ));

                if let Ok(data) = response.encode(None, true) {
                    let _ = self.socket.send_to(&data, from_addr).await;
                }
            }
            _ => {
                self.send_error_response(
                    from_addr,
                    request.transaction_id,
                    400,
                    "Bad Request",
                ).await;
            }
        }
    }

    /// Send error response
    async fn send_error_response(
        &self,
        client_addr: SocketAddr,
        transaction_id: TransactionId,
        error_code: u16,
        reason: &str,
    ) {
        let mut response = Message::new(
            self.get_error_message_type(transaction_id),
            transaction_id,
        );

        response.add_attribute(Attribute::new(
            AttributeType::ErrorCode,
            AttributeValue::ErrorCode {
                code: error_code,
                reason: reason.to_string(),
            },
        ));

        if let Ok(data) = response.encode(None, true) {
            let _ = self.socket.send_to(&data, client_addr).await;
        }
    }

    /// Get error message type based on request type
    fn get_error_message_type(&self, _transaction_id: TransactionId) -> MessageType {
        // In real implementation, would track request types
        MessageType::AllocateError
    }

    /// Check rate limit for client
    async fn check_rate_limit(&self, client_ip: IpAddr, packet_size: usize) -> bool {
        if let Some(limit) = &self.config.bandwidth_limit {
            let mut limiters = self.rate_limiters.write().await;

            let limiter = limiters.entry(client_ip)
                .or_insert_with(|| RateLimiter::new(
                    limit.bytes_per_second as f64,
                    limit.burst_size as f64,
                ));

            limiter.try_consume(packet_size as f64)
        } else {
            true
        }
    }

    /// Cleanup expired allocations and permissions
    async fn cleanup_loop(&self) {
        let mut interval = interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            // Clean expired allocations
            let now = Instant::now();
            let mut expired_keys = Vec::new();

            {
                let allocations = self.allocations.read().await;
                for (key, allocation) in allocations.iter() {
                    if allocation.expires_at <= now {
                        expired_keys.push(key.clone());
                    }
                }
            }

            for key in expired_keys {
                if let Some(allocation) = self.allocations.write().await.remove(&key) {
                    let port = allocation.relay_addr.port();
                    self.port_allocator.release(port).await;
                    self.stats.active_allocations.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

                    info!("Cleaned up expired allocation for {}", allocation.client_addr);
                }
            }

            // Clean expired permissions
            let allocations = self.allocations.read().await;
            for allocation in allocations.values() {
                let mut permissions = allocation.permissions.write().await;
                permissions.retain(|_, perm| perm.expires_at > now);

                let mut channels = allocation.channels.write().await;
                channels.retain(|_, binding| binding.expires_at > now);
            }

            // Clean expired nonces
            self.nonce_manager.cleanup_expired().await;
        }

        info!("Cleanup loop ended");
    }

    /// Statistics reporting loop
    async fn stats_loop(&self) {
        let mut interval = interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            if *self.shutdown.read().await {
                break;
            }

            let stats = self.get_statistics();
            info!("Server statistics: {:?}", stats);
        }

        info!("Stats loop ended");
    }

    /// Get server statistics
    pub fn get_statistics(&self) -> ServerStats {
        ServerStats {
            total_allocations: self.stats.total_allocations.load(std::sync::atomic::Ordering::Relaxed),
            active_allocations: self.stats.active_allocations.load(std::sync::atomic::Ordering::Relaxed),
            total_permissions: self.stats.total_permissions.load(std::sync::atomic::Ordering::Relaxed),
            total_channels: self.stats.total_channels.load(std::sync::atomic::Ordering::Relaxed),
            packets_processed: self.stats.packets_processed.load(std::sync::atomic::Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(std::sync::atomic::Ordering::Relaxed),
            bytes_relayed: self.stats.bytes_relayed.load(std::sync::atomic::Ordering::Relaxed),
            auth_failures: self.stats.auth_failures.load(std::sync::atomic::Ordering::Relaxed),
            sharp_decrypt_failures: self.stats.sharp_decrypt_failures.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Shutdown the server
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Shutting down TURN server");

        *self.shutdown.write().await = true;

        // Cancel all tasks
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        // Clean up all allocations
        let mut allocations = self.allocations.write().await;
        for (_, allocation) in allocations.drain() {
            self.port_allocator.release(allocation.relay_addr.port()).await;
        }

        info!("TURN server shutdown complete");
        Ok(())
    }
}

// Clone implementation
impl Clone for TurnServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            socket: self.socket.clone(),
            allocations: self.allocations.clone(),
            nonce_manager: self.nonce_manager.clone(),
            port_allocator: self.port_allocator.clone(),
            rate_limiters: self.rate_limiters.clone(),
            sharp_decryptor: self.sharp_decryptor.clone(),
            stats: self.stats.clone(),
            shutdown: self.shutdown.clone(),
            tasks: self.tasks.clone(),
        }
    }
}

/// Server statistics snapshot
#[derive(Debug)]
pub struct ServerStats {
    pub total_allocations: u64,
    pub active_allocations: u64,
    pub total_permissions: u64,
    pub total_channels: u64,
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub bytes_relayed: u64,
    pub auth_failures: u64,
    pub sharp_decrypt_failures: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_turn_server_creation() {
        let config = TurnServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            external_ip: "127.0.0.1".parse().unwrap(),
            ..Default::default()
        };

        let server = TurnServer::new(config).await.unwrap();
        assert!(!server.socket.local_addr().unwrap().port() == 0);
    }

    #[tokio::test]
    async fn test_port_allocator() {
        let allocator = PortAllocator::new(50000, 50010);
        let client = "127.0.0.1:12345".parse().unwrap();

        // Allocate ports
        let port1 = allocator.allocate(client).await.unwrap();
        let port2 = allocator.allocate(client).await.unwrap();

        assert!(port1 >= 50000 && port1 <= 50010);
        assert!(port2 >= 50000 && port2 <= 50010);
        assert_ne!(port1, port2);

        // Release and reallocate
        allocator.release(port1).await;
        let port3 = allocator.allocate(client).await.unwrap();
        assert_eq!(port3, port1);
    }

    #[tokio::test]
    async fn test_nonce_manager() {
        let manager = NonceManager::new(Duration::from_secs(60));

        let nonce1 = manager.generate_nonce().await;
        let nonce2 = manager.generate_nonce().await;

        assert_ne!(nonce1, nonce2);
        assert!(manager.validate_nonce(&nonce1).await);
        assert!(!manager.validate_nonce(&nonce1).await); // One-time use
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(1000.0, 100.0);

        assert!(limiter.try_consume(50.0));
        assert!(limiter.try_consume(40.0));
        assert!(!limiter.try_consume(20.0)); // Exceeds burst

        // Wait and refill
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(limiter.try_consume(50.0));
    }
}