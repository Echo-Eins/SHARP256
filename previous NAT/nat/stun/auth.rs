<<<<<<< Updated upstream:src/nat/stun/auth.rs
// src/nat/stun/auth.rs
//! STUN Authentication implementation fully compliant with RFC 8489
//!
//! Provides comprehensive authentication mechanisms including:
//! - Short-term credentials (RFC 8489 Section 9.1)
//! - Long-term credentials (RFC 8489 Section 9.2)
//! - Anonymous authentication with USERHASH (RFC 8489 Section 9.3)
//! - MESSAGE-INTEGRITY-SHA256 (RFC 8489 Section 14.6)
//! - Password algorithms (MD5, SHA-256)
//! - Nonce management and replay protection
//! - Security features configuration

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
=======
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
use sha2::{Sha256, Digest};
use sha1::Sha1;
use hmac::{Hmac, Mac};
use md5::Md5;
<<<<<<< Updated upstream:src/nat/stun/auth.rs
use rand::{RngCore, Rng};
use parking_lot::RwLock;

=======
use rand::RngCore;
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
use crate::nat::error::{StunError, NatResult};

/// STUN credential types as per RFC 8489
#[derive(Debug, Clone)]
pub enum CredentialType {
    /// Short-term credentials (for ICE)
<<<<<<< Updated upstream:src/nat/stun/auth.rs
    /// Username and password are transmitted in plaintext
    /// Used when security is provided by underlying transport
=======
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
    ShortTerm {
        username: String,
        password: String,
    },

<<<<<<< Updated upstream:src/nat/stun/auth.rs
    /// Long-term credentials (for TURN and authenticated STUN)
    /// Requires realm and uses challenge-response mechanism
=======
    /// Long-term credentials (for TURN)
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
    LongTerm {
        username: String,
        realm: String,
        password: String,
    },

<<<<<<< Updated upstream:src/nat/stun/auth.rs
    /// Anonymous authentication with USERHASH
    /// Provides privacy by hashing username with realm
=======
    /// Anonymous with USERHASH
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
    Anonymous {
        username: String,
        realm: String,
        password: String,
        use_userhash: bool,
    },
}

/// STUN credentials for authenticated requests
#[derive(Debug, Clone)]
pub struct Credentials {
<<<<<<< Updated upstream:src/nat/stun/auth.rs
    /// Type of credential mechanism
    pub credential_type: CredentialType,

    /// Current nonce for replay protection
    pub nonce: Option<Vec<u8>>,

    /// Password algorithm to use
    pub password_algorithm: PasswordAlgorithm,

    /// Server-supported password algorithms
    pub password_algorithms: Option<Vec<u16>>,

    /// Security features configuration
    pub security_features: SecurityFeatures,

    /// Authentication statistics
    pub auth_stats: AuthStatistics,
}

/// Password algorithms (RFC 8489 Section 14.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    /// MD5 algorithm (legacy, for compatibility)
    /// Should only be used when SHA-256 is not available
    MD5 = 0x0001,

    /// SHA-256 algorithm (RFC 8489 default)
    /// Recommended for new implementations
    SHA256 = 0x0002,
=======
    pub credential_type: CredentialType,
    pub nonce: Option<Vec<u8>>,
    pub password_algorithm: PasswordAlgorithm,
    pub password_algorithms: Option<Vec<u16>>, // Server-supported algorithms
}

/// Password algorithms (RFC 8489 Section 14.4)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PasswordAlgorithm {
    /// MD5 (legacy, for compatibility)
    MD5,

    /// SHA-256 (RFC 8489 default)
    SHA256,
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
}

impl Default for PasswordAlgorithm {
    fn default() -> Self {
        Self::SHA256
    }
}

<<<<<<< Updated upstream:src/nat/stun/auth.rs
/// Password algorithm parameters for negotiation
#[derive(Debug, Clone)]
pub struct PasswordAlgorithmParams {
    pub algorithm: PasswordAlgorithm,
    pub parameters: Vec<u8>,
}

impl PasswordAlgorithmParams {
    /// Create new password algorithm parameters
    pub fn new(algorithm: PasswordAlgorithm) -> Self {
        Self {
            algorithm,
            parameters: Vec::new(), // Most algorithms don't need parameters
        }
    }

    /// Encode to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.algorithm as u16).to_be_bytes());
        buf.extend_from_slice(&(self.parameters.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.parameters);
        buf
    }

    /// Decode from wire format
    pub fn decode(data: &[u8]) -> NatResult<Self> {
        if data.len() < 4 {
            return Err(StunError::InvalidMessage("PASSWORD-ALGORITHM too short".to_string()).into());
        }

        let algorithm_id = u16::from_be_bytes([data[0], data[1]]);
        let param_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + param_len {
            return Err(StunError::InvalidMessage("PASSWORD-ALGORITHM parameters truncated".to_string()).into());
        }

        let algorithm = match algorithm_id {
            0x0001 => PasswordAlgorithm::MD5,
            0x0002 => PasswordAlgorithm::SHA256,
            _ => return Err(StunError::UnsupportedPasswordAlgorithm(algorithm_id).into()),
        };

        let parameters = data[4..4 + param_len].to_vec();

        Ok(Self {
            algorithm,
            parameters,
        })
    }
}

/// Security features configuration
#[derive(Debug, Clone)]
pub struct SecurityFeatures {
    /// Enable password algorithm negotiation
    pub enable_password_algorithms: bool,

    /// Require MESSAGE-INTEGRITY-SHA256 when available
    pub prefer_sha256_integrity: bool,

    /// Enable USERHASH for anonymous authentication
    pub enable_userhash: bool,

    /// Nonce cache size for replay protection
    pub nonce_cache_size: usize,

    /// Nonce lifetime
    pub nonce_lifetime: Duration,

    /// Maximum authentication failures before lockout
    pub max_auth_failures: u32,

    /// Authentication failure lockout duration
    pub auth_lockout_duration: Duration,

    /// Enable timing attack protection
    pub constant_time_verification: bool,

    /// Require fresh nonces for each transaction
    pub require_fresh_nonce: bool,

    /// Enable audit logging for authentication events
    pub enable_audit_logging: bool,
}

impl Default for SecurityFeatures {
    fn default() -> Self {
        Self {
            enable_password_algorithms: true,
            prefer_sha256_integrity: true,
            enable_userhash: true,
            nonce_cache_size: 1000,
            nonce_lifetime: Duration::from_secs(600), // 10 minutes
            max_auth_failures: 5,
            auth_lockout_duration: Duration::from_secs(300), // 5 minutes
            constant_time_verification: true,
            require_fresh_nonce: false,
            enable_audit_logging: true,
        }
    }
}

/// Authentication statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct AuthStatistics {
    /// Total authentication attempts
    pub total_attempts: u64,

    /// Successful authentications
    pub successful_auths: u64,

    /// Failed authentications
    pub failed_auths: u64,

    /// Nonce replays detected
    pub nonce_replays: u64,

    /// Invalid credentials
    pub invalid_credentials: u64,

    /// Timing attack attempts detected
    pub timing_attacks: u64,

    /// Last authentication timestamp
    pub last_auth_time: Option<Instant>,

    /// Authentication methods used
    pub methods_used: HashMap<String, u64>,
}

/// Nonce cookie for secure nonce generation
#[derive(Debug, Clone)]
pub struct NonceCookie {
    /// Timestamp when nonce was created
    pub timestamp: u64,

    /// Client IP address (for binding)
    pub client_ip: std::net::IpAddr,

    /// Random component
    pub random: [u8; 16],

    /// HMAC for integrity
    pub hmac: [u8; 32],
}

impl NonceCookie {
    /// Generate new nonce cookie
    pub fn generate(client_ip: std::net::IpAddr, hmac_key: &[u8]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);

        // Compute HMAC over timestamp, IP, and random data
        let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)
            .expect("HMAC can take key of any size");

        mac.update(&timestamp.to_be_bytes());
        match client_ip {
            std::net::IpAddr::V4(ip) => mac.update(&ip.octets()),
            std::net::IpAddr::V6(ip) => mac.update(&ip.octets()),
        }
        mac.update(&random);

        let hmac_result = mac.finalize();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(hmac_result.into_bytes().as_slice());

        Self {
            timestamp,
            client_ip,
            random,
            hmac,
        }
    }

    /// Encode nonce cookie to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        // Timestamp (8 bytes)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // IP address
        match self.client_ip {
            std::net::IpAddr::V4(ip) => {
                buf.push(4); // IPv4 marker
                buf.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                buf.push(6); // IPv6 marker
                buf.extend_from_slice(&ip.octets());
            }
        }

        // Random data (16 bytes)
        buf.extend_from_slice(&self.random);

        // HMAC (32 bytes)
        buf.extend_from_slice(&self.hmac);

        buf
    }

    /// Decode nonce cookie from bytes
    pub fn decode(data: &[u8]) -> NatResult<Self> {
        if data.len() < 57 { // Minimum size for IPv4
            return Err(StunError::InvalidNonce("Nonce too short".to_string()).into());
        }

        let timestamp = u64::from_be_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7]
        ]);

        let (client_ip, ip_end) = match data[8] {
            4 => {
                if data.len() < 61 {
                    return Err(StunError::InvalidNonce("IPv4 nonce too short".to_string()).into());
                }
                let ip = std::net::Ipv4Addr::from([data[9], data[10], data[11], data[12]]);
                (std::net::IpAddr::V4(ip), 13)
            }
            6 => {
                if data.len() < 73 {
                    return Err(StunError::InvalidNonce("IPv6 nonce too short".to_string()).into());
                }
                let ip_bytes: [u8; 16] = data[9..25].try_into()
                    .map_err(|_| StunError::InvalidNonce("Invalid IPv6 address".to_string()))?;
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                (std::net::IpAddr::V6(ip), 25)
            }
            _ => return Err(StunError::InvalidNonce("Invalid IP version marker".to_string()).into()),
        };

        if data.len() < ip_end + 48 { // 16 bytes random + 32 bytes HMAC
            return Err(StunError::InvalidNonce("Nonce missing random/HMAC data".to_string()).into());
        }

        let mut random = [0u8; 16];
        random.copy_from_slice(&data[ip_end..ip_end + 16]);

        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&data[ip_end + 16..ip_end + 48]);

        Ok(Self {
            timestamp,
            client_ip,
            random,
            hmac,
        })
    }

    /// Verify nonce cookie integrity
    pub fn verify(&self, hmac_key: &[u8], max_age: Duration) -> bool {
        // Check timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now.saturating_sub(self.timestamp) > max_age.as_secs() {
            return false;
        }

        // Verify HMAC
        let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)
            .expect("HMAC can take key of any size");

        mac.update(&self.timestamp.to_be_bytes());
        match self.client_ip {
            std::net::IpAddr::V4(ip) => mac.update(&ip.octets()),
            std::net::IpAddr::V6(ip) => mac.update(&ip.octets()),
        }
        mac.update(&self.random);

        mac.verify_slice(&self.hmac).is_ok()
    }
}

/// Nonce manager for secure nonce generation and validation
pub struct NonceManager {
    /// HMAC key for nonce generation
    hmac_key: [u8; 32],

    /// Cache of recent nonces to prevent replay
    nonce_cache: RwLock<HashMap<Vec<u8>, Instant>>,

    /// Configuration
    config: SecurityFeatures,
}

impl NonceManager {
    /// Create new nonce manager
    pub fn new(config: SecurityFeatures) -> Self {
        let mut hmac_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hmac_key);

        Self {
            hmac_key,
            nonce_cache: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Generate new nonce for client
    pub fn generate_nonce(&self, client_ip: std::net::IpAddr) -> Vec<u8> {
        let cookie = NonceCookie::generate(client_ip, &self.hmac_key);
        let nonce = cookie.encode();

        // Add to cache
        {
            let mut cache = self.nonce_cache.write();

            // Clean expired nonces
            let now = Instant::now();
            cache.retain(|_, &mut timestamp| {
                now.duration_since(timestamp) < self.config.nonce_lifetime
            });

            // Add new nonce
            cache.insert(nonce.clone(), now);

            // Limit cache size
            if cache.len() > self.config.nonce_cache_size {
                // Remove oldest entries
                let mut entries: Vec<_> = cache.iter().collect();
                entries.sort_by_key(|(_, &timestamp)| timestamp);

                let to_remove = cache.len() - self.config.nonce_cache_size;
                for (nonce, _) in entries.into_iter().take(to_remove) {
                    cache.remove(nonce);
                }
            }
        }

        nonce
    }

    /// Validate nonce
    pub fn validate_nonce(&self, nonce: &[u8], client_ip: std::net::IpAddr) -> bool {
        // Decode nonce cookie
        let cookie = match NonceCookie::decode(nonce) {
            Ok(cookie) => cookie,
            Err(_) => return false,
        };

        // Verify cookie integrity and age
        if !cookie.verify(&self.hmac_key, self.config.nonce_lifetime) {
            return false;
        }

        // Verify client IP matches
        if cookie.client_ip != client_ip {
            return false;
        }

        // Check for replay if fresh nonces are required
        if self.config.require_fresh_nonce {
            let mut cache = self.nonce_cache.write();
            if cache.contains_key(nonce) {
                cache.remove(nonce); // One-time use
                return true;
            } else {
                return false; // Nonce not found or already used
            }
        }

        true
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.nonce_cache.read();
        (cache.len(), self.config.nonce_cache_size)
    }
}

=======
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
impl Credentials {
    /// Create short-term credentials
    pub fn short_term(username: String, password: String) -> Self {
        Self {
            credential_type: CredentialType::ShortTerm { username, password },
            nonce: None,
            password_algorithm: PasswordAlgorithm::default(),
            password_algorithms: None,
<<<<<<< Updated upstream:src/nat/stun/auth.rs
            security_features: SecurityFeatures::default(),
            auth_stats: AuthStatistics::default(),
=======
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
        }
    }

    /// Create long-term credentials
    pub fn long_term(username: String, realm: String, password: String) -> Self {
        Self {
            credential_type: CredentialType::LongTerm { username, realm, password },
            nonce: None,
            password_algorithm: PasswordAlgorithm::default(),
            password_algorithms: None,
<<<<<<< Updated upstream:src/nat/stun/auth.rs
            security_features: SecurityFeatures::default(),
            auth_stats: AuthStatistics::default(),
=======
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
        }
    }

    /// Create anonymous credentials with USERHASH
    pub fn anonymous(username: String, realm: String, password: String) -> Self {
        Self {
            credential_type: CredentialType::Anonymous {
                username,
                realm,
                password,
                use_userhash: true
            },
            nonce: None,
            password_algorithm: PasswordAlgorithm::default(),
            password_algorithms: None,
<<<<<<< Updated upstream:src/nat/stun/auth.rs
            security_features: SecurityFeatures::default(),
            auth_stats: AuthStatistics::default(),
        }
    }

    /// Get username for authentication
    pub fn username(&self) -> &str {
=======
        }
    }

    /// Set nonce for long-term credentials
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set password algorithm
    pub fn with_algorithm(mut self, algorithm: PasswordAlgorithm) -> Self {
        self.password_algorithm = algorithm;
        self
    }

    /// Set server-supported algorithms
    pub fn with_supported_algorithms(mut self, algorithms: Vec<u16>) -> Self {
        self.password_algorithms = Some(algorithms);
        self
    }

    /// Compute HMAC key for MESSAGE-INTEGRITY
    pub fn compute_key(&self) -> NatResult<Vec<u8>> {
        match &self.credential_type {
            CredentialType::ShortTerm { password, .. } => {
                // Short-term: key = password (UTF-8 encoded)
                Ok(password.as_bytes().to_vec())
            }

            CredentialType::LongTerm { username, realm, password } |
            CredentialType::Anonymous { username, realm, password, .. } => {
                // Long-term: key = hash(username:realm:password)
                match self.password_algorithm {
                    PasswordAlgorithm::MD5 => {
                        let input = format!("{}:{}:{}", username, realm, password);
                        let hash = Md5::digest(input.as_bytes());
                        Ok(hash.to_vec())
                    }
                    PasswordAlgorithm::SHA256 => {
                        let input = format!("{}:{}:{}", username, realm, password);
                        let hash = Sha256::digest(input.as_bytes());
                        Ok(hash.to_vec())
                    }
                }
            }
        }
    }

    /// Get username for request
    pub fn get_username(&self) -> &str {
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
        match &self.credential_type {
            CredentialType::ShortTerm { username, .. } |
            CredentialType::LongTerm { username, .. } |
            CredentialType::Anonymous { username, .. } => username,
        }
    }

    /// Get realm if applicable
<<<<<<< Updated upstream:src/nat/stun/auth.rs
    pub fn realm(&self) -> Option<&str> {
=======
    pub fn get_realm(&self) -> Option<&str> {
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
        match &self.credential_type {
            CredentialType::ShortTerm { .. } => None,
            CredentialType::LongTerm { realm, .. } |
            CredentialType::Anonymous { realm, .. } => Some(realm),
        }
    }

<<<<<<< Updated upstream:src/nat/stun/auth.rs
    /// Get password
    pub fn password(&self) -> &str {
        match &self.credential_type {
            CredentialType::ShortTerm { password, .. } |
            CredentialType::LongTerm { password, .. } |
            CredentialType::Anonymous { password, .. } => password,
        }
    }

=======
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
    /// Check if USERHASH should be used
    pub fn use_userhash(&self) -> bool {
        match &self.credential_type {
            CredentialType::Anonymous { use_userhash, .. } => *use_userhash,
            _ => false,
        }
    }

<<<<<<< Updated upstream:src/nat/stun/auth.rs
    /// Compute USERHASH value
    pub fn compute_userhash(&self) -> NatResult<Vec<u8>> {
        if let Some(realm) = self.realm() {
            let mut hasher = Sha256::new();
            hasher.update(self.username().as_bytes());
            hasher.update(b":");
            hasher.update(realm.as_bytes());
            Ok(hasher.finalize().to_vec())
        } else {
            Err(StunError::MissingRealm.into())
        }
    }

    /// Derive key for MESSAGE-INTEGRITY computation
    pub fn derive_key(&self, realm: Option<&str>) -> NatResult<Vec<u8>> {
        match &self.credential_type {
            CredentialType::ShortTerm { password, .. } => {
                // For short-term credentials, password is used directly
                Ok(password.as_bytes().to_vec())
            }
            CredentialType::LongTerm { username, realm: cred_realm, password } |
            CredentialType::Anonymous { username, realm: cred_realm, password, .. } => {
                // For long-term credentials, use MD5(username:realm:password)
                let realm_value = realm.unwrap_or(cred_realm);

                match self.password_algorithm {
                    PasswordAlgorithm::MD5 => {
                        let mut hasher = Md5::new();
                        hasher.update(username.as_bytes());
                        hasher.update(b":");
                        hasher.update(realm_value.as_bytes());
                        hasher.update(b":");
                        hasher.update(password.as_bytes());
                        Ok(hasher.finalize().to_vec())
                    }
                    PasswordAlgorithm::SHA256 => {
                        let mut hasher = Sha256::new();
                        hasher.update(username.as_bytes());
                        hasher.update(b":");
                        hasher.update(realm_value.as_bytes());
                        hasher.update(b":");
                        hasher.update(password.as_bytes());
                        Ok(hasher.finalize().to_vec())
                    }
                }
            }
        }
    }
}

/// Compute MESSAGE-INTEGRITY-SHA256 attribute value (RFC 8489 Section 14.6)
pub fn compute_message_integrity_sha256(
    message: &[u8],
    key: &[u8],
) -> NatResult<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| StunError::CryptographicError(format!("HMAC-SHA256 key error: {}", e)))?;

    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

/// Verify MESSAGE-INTEGRITY-SHA256 attribute value
pub fn verify_message_integrity_sha256(
    message: &[u8],
    expected_hmac: &[u8],
    key: &[u8],
) -> NatResult<bool> {
    let computed_hmac = compute_message_integrity_sha256(message, key)?;

    // Use constant-time comparison to prevent timing attacks
    Ok(constant_time_eq(&computed_hmac, expected_hmac))
}

/// Compute MESSAGE-INTEGRITY attribute value using SHA-1 (legacy)
pub fn compute_message_integrity_sha1(
    message: &[u8],
    key: &[u8],
) -> NatResult<Vec<u8>> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|e| StunError::CryptographicError(format!("HMAC-SHA1 key error: {}", e)))?;

    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

/// Verify MESSAGE-INTEGRITY attribute value using SHA-1
pub fn verify_message_integrity_sha1(
    message: &[u8],
    expected_hmac: &[u8],
    key: &[u8],
) -> NatResult<bool> {
    let computed_hmac = compute_message_integrity_sha1(message, key)?;

    // Use constant-time comparison to prevent timing attacks
    Ok(constant_time_eq(&computed_hmac, expected_hmac))
}

/// Constant-time equality comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate random username for anonymous authentication
pub fn generate_anonymous_username() -> String {
    let random_bytes = generate_random_bytes(16);
    base64::encode_config(&random_bytes, base64::URL_SAFE_NO_PAD)
}

/// Password strength validator
pub struct PasswordValidator {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digits: bool,
    require_special: bool,
    forbidden_patterns: Vec<String>,
}

impl Default for PasswordValidator {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special: true,
            forbidden_patterns: vec![
                "password".to_string(),
                "123456".to_string(),
                "qwerty".to_string(),
            ],
=======
    /// Compute USERHASH value (RFC 8489 Section 14.8)
    pub fn compute_userhash(&self) -> NatResult<Vec<u8>> {
        if let Some(realm) = self.get_realm() {
            let username = self.get_username();
            let input = format!("{}:{}", username, realm);

            match self.password_algorithm {
                PasswordAlgorithm::MD5 => {
                    // USERHASH with MD5 not recommended
                    Err(StunError::Authentication(
                        "USERHASH requires SHA-256".to_string()
                    ).into())
                }
                PasswordAlgorithm::SHA256 => {
                    let hash = Sha256::digest(input.as_bytes());
                    Ok(hash.to_vec())
                }
            }
        } else {
            Err(StunError::Authentication(
                "USERHASH requires realm".to_string()
            ).into())
        }
    }

    /// Select best password algorithm from server list
    pub fn select_algorithm(&mut self, server_algorithms: &[u16]) -> NatResult<()> {
        // Prefer SHA-256 if available
        if server_algorithms.contains(&0x0002) {
            self.password_algorithm = PasswordAlgorithm::SHA256;
        } else if server_algorithms.contains(&0x0001) {
            self.password_algorithm = PasswordAlgorithm::MD5;
        } else {
            return Err(StunError::Authentication(
                "No compatible password algorithm".to_string()
            ).into());
        }
        Ok(())
    }
}

/// Compute MESSAGE-INTEGRITY-SHA256
pub fn compute_message_integrity_sha256(
    message: &[u8],
    key: &[u8],
) -> NatResult<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| StunError::Authentication(format!("Invalid key: {}", e)))?;

    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify MESSAGE-INTEGRITY-SHA256
pub fn verify_message_integrity_sha256(
    message: &[u8],
    key: &[u8],
    expected_hash: &[u8],
) -> NatResult<bool> {
    if expected_hash.len() != 32 {
        return Ok(false);
    }

    let computed = compute_message_integrity_sha256(message, key)?;

    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    Ok(computed.ct_eq(expected_hash).into())
}

/// Compute MESSAGE-INTEGRITY (legacy SHA1)
pub fn compute_message_integrity_sha1(
    message: &[u8],
    key: &[u8],
) -> NatResult<[u8; 20]> {
    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(key)
        .map_err(|e| StunError::Authentication(format!("Invalid key: {}", e)))?;

    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify MESSAGE-INTEGRITY (legacy SHA1)
pub fn verify_message_integrity_sha1(
    message: &[u8],
    key: &[u8],
    expected_hash: &[u8],
) -> NatResult<bool> {
    if expected_hash.len() != 20 {
        return Ok(false);
    }

    let computed = compute_message_integrity_sha1(message, key)?;

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    Ok(computed.ct_eq(expected_hash).into())
}

/// Password algorithms parameters (RFC 8489 Section 14.4)
#[derive(Debug, Clone)]
pub struct PasswordAlgorithmParams {
    pub algorithm_id: u16,
    pub parameters: Vec<u8>,
}

impl PasswordAlgorithmParams {
    /// Create MD5 algorithm parameters
    pub fn md5() -> Self {
        Self {
            algorithm_id: 0x0001,
            parameters: Vec::new(),
        }
    }

    /// Create SHA256 algorithm parameters
    pub fn sha256() -> Self {
        Self {
            algorithm_id: 0x0002,
            parameters: Vec::new(),
        }
    }

    /// Parse algorithm from ID
    pub fn to_algorithm(&self) -> Option<PasswordAlgorithm> {
        match self.algorithm_id {
            0x0001 => Some(PasswordAlgorithm::MD5),
            0x0002 => Some(PasswordAlgorithm::SHA256),
            _ => None,
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
        }
    }
}

<<<<<<< Updated upstream:src/nat/stun/auth.rs
impl PasswordValidator {
    /// Validate password strength
    pub fn validate(&self, password: &str) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if password.len() < self.min_length {
            errors.push(format!("Password must be at least {} characters long", self.min_length));
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            errors.push("Password must contain at least one uppercase letter".to_string());
        }

        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            errors.push("Password must contain at least one lowercase letter".to_string());
        }

        if self.require_digits && !password.chars().any(|c| c.is_numeric()) {
            errors.push("Password must contain at least one digit".to_string());
        }

        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            errors.push("Password must contain at least one special character".to_string());
        }

        let lower_password = password.to_lowercase();
        for pattern in &self.forbidden_patterns {
            if lower_password.contains(&pattern.to_lowercase()) {
                errors.push(format!("Password must not contain '{}'", pattern));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
=======
/// Security features for bid-down attack prevention
#[derive(Debug, Clone, Copy)]
pub struct SecurityFeatures {
    /// Support for MESSAGE-INTEGRITY-SHA256
    pub message_integrity_sha256: bool,

    /// Support for USERHASH
    pub userhash: bool,

    /// Support for PASSWORD-ALGORITHM
    pub password_algorithm: bool,

    /// Support for PASSWORD-ALGORITHMS
    pub password_algorithms: bool,
}

impl SecurityFeatures {
    /// Create from nonce cookie bits
    pub fn from_nonce_bits(bits: u8) -> Self {
        Self {
            message_integrity_sha256: bits & 0x01 != 0,
            userhash: bits & 0x02 != 0,
            password_algorithm: bits & 0x04 != 0,
            password_algorithms: bits & 0x08 != 0,
        }
    }

    /// Convert to nonce cookie bits
    pub fn to_nonce_bits(&self) -> u8 {
        let mut bits = 0u8;
        if self.message_integrity_sha256 {
            bits |= 0x01;
        }
        if self.userhash {
            bits |= 0x02;
        }
        if self.password_algorithm {
            bits |= 0x04;
        }
        if self.password_algorithms {
            bits |= 0x08;
        }
        bits
    }
}

/// Nonce cookie for security feature negotiation
#[derive(Debug, Clone)]
pub struct NonceCookie {
    pub nonce: Vec<u8>,
    pub features: SecurityFeatures,
}

impl NonceCookie {
    /// Parse nonce cookie from server
    pub fn parse(nonce: &[u8]) -> Option<Self> {
        if nonce.len() < 8 {
            return None;
        }

        // Check for "obMatJos" prefix (RFC 8489)
        if &nonce[..8] != b"obMatJos" {
            return None;
        }

        // Extract security features from 9th byte if present
        let features = if nonce.len() > 8 {
            SecurityFeatures::from_nonce_bits(nonce[8])
        } else {
            SecurityFeatures {
                message_integrity_sha256: false,
                userhash: false,
                password_algorithm: false,
                password_algorithms: false,
            }
        };

        Some(Self {
            nonce: nonce.to_vec(),
            features,
        })
    }

    /// Create nonce cookie with security features
    pub fn create(features: SecurityFeatures) -> Self {
        let mut nonce = b"obMatJos".to_vec();
        nonce.push(features.to_nonce_bits());

        // Add random bytes for uniqueness
        let mut random_bytes = vec![0u8; 16];
        use rand::rngs::OsRng;
        OsRng.fill_bytes(&mut random_bytes);
        nonce.extend(random_bytes);

        Self { nonce, features }
    }

    /// Check if this is a valid nonce cookie
    pub fn is_valid_cookie(nonce: &[u8]) -> bool {
        nonce.len() >= 8 && &nonce[..8] == b"obMatJos"
    }
}

/// Generate a secure nonce
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 32];
    use rand::rngs::OsRng;
    OsRng.fill_bytes(&mut nonce);
    nonce
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
<<<<<<< Updated upstream:src/nat/stun/auth.rs
    fn test_password_algorithms() {
        let params = PasswordAlgorithmParams::new(PasswordAlgorithm::SHA256);
        let encoded = params.encode();
        let decoded = PasswordAlgorithmParams::decode(&encoded).unwrap();

        assert_eq!(params.algorithm as u16, decoded.algorithm as u16);
        assert_eq!(params.parameters, decoded.parameters);
    }

    #[test]
    fn test_nonce_cookie() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let hmac_key = b"test-key-for-hmac-computation-32b";

        let cookie = NonceCookie::generate(client_ip, hmac_key);
        let encoded = cookie.encode();
        let decoded = NonceCookie::decode(&encoded).unwrap();

        assert_eq!(cookie.client_ip, decoded.client_ip);
        assert_eq!(cookie.random, decoded.random);
        assert_eq!(cookie.hmac, decoded.hmac);

        // Verify integrity
        assert!(decoded.verify(hmac_key, Duration::from_secs(3600)));

        // Should fail with wrong key
        let wrong_key = b"wrong-key-for-hmac-computation32b";
        assert!(!decoded.verify(wrong_key, Duration::from_secs(3600)));
    }

    #[test]
    fn test_nonce_manager() {
        let config = SecurityFeatures::default();
        let manager = NonceManager::new(config);
        let client_ip = "192.168.1.1".parse().unwrap();

        let nonce = manager.generate_nonce(client_ip);
        assert!(manager.validate_nonce(&nonce, client_ip));

        // Should fail with wrong IP
        let wrong_ip = "192.168.1.2".parse().unwrap();
        assert!(!manager.validate_nonce(&nonce, wrong_ip));
    }

    #[test]
    fn test_credentials() {
        let creds = Credentials::long_term(
            "alice".to_string(),
            "example.com".to_string(),
            "password123".to_string(),
        );

        assert_eq!(creds.username(), "alice");
        assert_eq!(creds.realm(), Some("example.com"));
        assert_eq!(creds.password(), "password123");

        let key = creds.derive_key(None).unwrap();
        assert!(!key.is_empty());
    }

    #[test]
    fn test_message_integrity_sha256() {
        let message = b"test message";
        let key = b"test key";

        let hmac = compute_message_integrity_sha256(message, key).unwrap();
        assert!(verify_message_integrity_sha256(message, &hmac, key).unwrap());

        // Should fail with wrong key
        let wrong_key = b"wrong key";
        assert!(!verify_message_integrity_sha256(message, &hmac, wrong_key).unwrap());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, b"hell")); // Different lengths
    }

    #[test]
    fn test_password_validator() {
        let validator = PasswordValidator::default();

        // Valid password
        assert!(validator.validate("StrongPass123!").is_ok());

        // Too short
        assert!(validator.validate("Abc1!").is_err());

        // Missing uppercase
        assert!(validator.validate("weakpass123!").is_err());

        // Missing special character
        assert!(validator.validate("WeakPass123").is_err());

        // Contains forbidden pattern
        assert!(validator.validate("MyPassword123!").is_err());
=======
    fn test_short_term_credentials() {
        let creds = Credentials::short_term(
            "user".to_string(),
            "pass".to_string()
        );

        let key = creds.compute_key().unwrap();
        assert_eq!(key, b"pass");
    }

    #[test]
    fn test_long_term_credentials_sha256() {
        let creds = Credentials::long_term(
            "user".to_string(),
            "realm".to_string(),
            "pass".to_string()
        );

        let key = creds.compute_key().unwrap();

        // Verify against known value
        let expected = Sha256::digest(b"user:realm:pass");
        assert_eq!(key, expected.as_slice());
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
    }

    #[test]
    fn test_userhash_computation() {
        let creds = Credentials::anonymous(
<<<<<<< Updated upstream:src/nat/stun/auth.rs
            "alice".to_string(),
            "example.com".to_string(),
            "password123".to_string(),
        );

        let userhash = creds.compute_userhash().unwrap();
        assert_eq!(userhash.len(), 32); // SHA-256 output size

        // Should be deterministic
        let userhash2 = creds.compute_userhash().unwrap();
        assert_eq!(userhash, userhash2);
    }

    #[test]
    fn test_random_generation() {
        let bytes1 = generate_random_bytes(32);
        let bytes2 = generate_random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different

        let username = generate_anonymous_username();
        assert!(!username.is_empty());
        assert!(!username.contains('/')); // URL-safe encoding
=======
            "user".to_string(),
            "realm".to_string(),
            "pass".to_string()
        );

        let userhash = creds.compute_userhash().unwrap();

        // Verify against known value
        let expected = Sha256::digest(b"user:realm");
        assert_eq!(userhash, expected.as_slice());
    }

    #[test]
    fn test_nonce_cookie() {
        let features = SecurityFeatures {
            message_integrity_sha256: true,
            userhash: true,
            password_algorithm: false,
            password_algorithms: true,
        };

        let cookie = NonceCookie::create(features);
        assert!(cookie.nonce.starts_with(b"obMatJos"));
        assert_eq!(cookie.nonce[8], 0x0B); // bits 0, 1, and 3 set

        // Test parsing
        let parsed = NonceCookie::parse(&cookie.nonce).unwrap();
        assert_eq!(parsed.features.message_integrity_sha256, true);
        assert_eq!(parsed.features.userhash, true);
        assert_eq!(parsed.features.password_algorithm, false);
        assert_eq!(parsed.features.password_algorithms, true);
    }

    #[test]
    fn test_message_integrity_sha256() {
        let message = b"test message";
        let key = b"secret key";

        let hash = compute_message_integrity_sha256(message, key).unwrap();
        assert_eq!(hash.len(), 32);

        // Verify
        let valid = verify_message_integrity_sha256(message, key, &hash).unwrap();
        assert!(valid);

        // Verify with wrong key
        let invalid = verify_message_integrity_sha256(message, b"wrong key", &hash).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_constant_time_comparison() {
        let hash1 = [0u8; 32];
        let hash2 = [0u8; 32];
        let hash3 = [1u8; 32];

        // Same arrays should be equal
        assert!(verify_message_integrity_sha256(b"", b"", &hash1).unwrap());

        // Different arrays should not be equal
        let key = b"key";
        let computed = compute_message_integrity_sha256(b"msg1", key).unwrap();
        let different = compute_message_integrity_sha256(b"msg2", key).unwrap();
        assert_ne!(computed, different);
>>>>>>> Stashed changes:previous NAT/nat/stun/auth.rs
    }
}