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
use sha2::{Sha256, Digest};
use sha1::Sha1;
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::{RngCore, Rng};
use parking_lot::RwLock;

use crate::nat::error::{StunError, NatResult};

/// STUN credential types as per RFC 8489
#[derive(Debug, Clone)]
pub enum CredentialType {
    /// Short-term credentials (for ICE)
    /// Username and password are transmitted in plaintext
    /// Used when security is provided by underlying transport
    ShortTerm {
        username: String,
        password: String,
    },

    /// Long-term credentials (for TURN and authenticated STUN)
    /// Requires realm and uses challenge-response mechanism
    LongTerm {
        username: String,
        realm: String,
        password: String,
    },

    /// Anonymous authentication with USERHASH
    /// Provides privacy by hashing username with realm
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
}

impl Default for PasswordAlgorithm {
    fn default() -> Self {
        Self::SHA256
    }
}

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

impl Credentials {
    /// Create short-term credentials
    pub fn short_term(username: String, password: String) -> Self {
        Self {
            credential_type: CredentialType::ShortTerm { username, password },
            nonce: None,
            password_algorithm: PasswordAlgorithm::default(),
            password_algorithms: None,
            security_features: SecurityFeatures::default(),
            auth_stats: AuthStatistics::default(),
        }
    }

    /// Create long-term credentials
    pub fn long_term(username: String, realm: String, password: String) -> Self {
        Self {
            credential_type: CredentialType::LongTerm { username, realm, password },
            nonce: None,
            password_algorithm: PasswordAlgorithm::default(),
            password_algorithms: None,
            security_features: SecurityFeatures::default(),
            auth_stats: AuthStatistics::default(),
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
            security_features: SecurityFeatures::default(),
            auth_stats: AuthStatistics::default(),
        }
    }

    /// Get username for authentication
    pub fn username(&self) -> &str {
        match &self.credential_type {
            CredentialType::ShortTerm { username, .. } |
            CredentialType::LongTerm { username, .. } |
            CredentialType::Anonymous { username, .. } => username,
        }
    }

    /// Get realm if applicable
    pub fn realm(&self) -> Option<&str> {
        match &self.credential_type {
            CredentialType::ShortTerm { .. } => None,
            CredentialType::LongTerm { realm, .. } |
            CredentialType::Anonymous { realm, .. } => Some(realm),
        }
    }

    /// Get password
    pub fn password(&self) -> &str {
        match &self.credential_type {
            CredentialType::ShortTerm { password, .. } |
            CredentialType::LongTerm { password, .. } |
            CredentialType::Anonymous { password, .. } => password,
        }
    }

    /// Check if USERHASH should be used
    pub fn use_userhash(&self) -> bool {
        match &self.credential_type {
            CredentialType::Anonymous { use_userhash, .. } => *use_userhash,
            _ => false,
        }
    }

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
        }
    }
}

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
    }

    #[test]
    fn test_userhash_computation() {
        let creds = Credentials::anonymous(
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
    }
}