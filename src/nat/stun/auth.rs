use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use md5::Md5;
use crate::nat::error::{StunError, NatResult};

/// STUN credential types
#[derive(Debug, Clone)]
pub enum CredentialType {
    /// Short-term credentials (for ICE)
    ShortTerm {
        username: String,
        password: String,
    },
    
    /// Long-term credentials (for TURN)
    LongTerm {
        username: String,
        realm: String,
        password: String,
    },
    
    /// Anonymous with USERHASH
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
    pub credential_type: CredentialType,
    pub nonce: Option<Vec<u8>>,
    pub password_algorithm: PasswordAlgorithm,
}

/// Password algorithms (RFC 8489 Section 14.4)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PasswordAlgorithm {
    /// MD5 (legacy, for compatibility)
    MD5,
    
    /// SHA-256 (RFC 8489 default)
    SHA256,
}

impl Default for PasswordAlgorithm {
    fn default() -> Self {
        Self::SHA256
    }
}

impl Credentials {
    /// Create short-term credentials
    pub fn short_term(username: String, password: String) -> Self {
        Self {
            credential_type: CredentialType::ShortTerm { username, password },
            nonce: None,
            password_algorithm: PasswordAlgorithm::default(),
        }
    }
    
    /// Create long-term credentials
    pub fn long_term(username: String, realm: String, password: String) -> Self {
        Self {
            credential_type: CredentialType::LongTerm { username, realm, password },
            nonce: None,
            password_algorithm: PasswordAlgorithm::default(),
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
        match &self.credential_type {
            CredentialType::ShortTerm { username, .. } |
            CredentialType::LongTerm { username, .. } |
            CredentialType::Anonymous { username, .. } => username,
        }
    }
    
    /// Get realm if applicable
    pub fn get_realm(&self) -> Option<&str> {
        match &self.credential_type {
            CredentialType::ShortTerm { .. } => None,
            CredentialType::LongTerm { realm, .. } |
            CredentialType::Anonymous { realm, .. } => Some(realm),
        }
    }
    
    /// Check if USERHASH should be used
    pub fn use_userhash(&self) -> bool {
        match &self.credential_type {
            CredentialType::Anonymous { use_userhash, .. } => *use_userhash,
            _ => false,
        }
    }
    
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
    let mut equal = true;
    for i in 0..32 {
        equal &= computed[i] == expected_hash[i];
    }
    
    Ok(equal)
}

/// Compute MESSAGE-INTEGRITY (legacy SHA1)
pub fn compute_message_integrity_sha1(
    message: &[u8],
    key: &[u8],
) -> NatResult<[u8; 20]> {
    type HmacSha1 = Hmac<sha1::Sha1>;
    
    let mut mac = HmacSha1::new_from_slice(key)
        .map_err(|e| StunError::Authentication(format!("Invalid key: {}", e)))?;
    
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
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
        }
    }
}

/// Security features for bid-down attack prevention
#[derive(Debug, Clone, Copy)]
pub struct SecurityFeatures {
    /// Support for MESSAGE-INTEGRITY-SHA256
    pub message_integrity_sha256: bool,
    
    /// Support for USERHASH
    pub userhash: bool,
    
    /// Support for PASSWORD-ALGORITHM
    pub password_algorithm: bool,
}

impl SecurityFeatures {
    /// Create from nonce cookie bits
    pub fn from_nonce_bits(bits: u8) -> Self {
        Self {
            message_integrity_sha256: bits & 0x01 != 0,
            userhash: bits & 0x02 != 0,
            password_algorithm: bits & 0x04 != 0,
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
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut random_bytes);
        nonce.extend(random_bytes);
        
        Self { nonce, features }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
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
    }
    
    #[test]
    fn test_userhash_computation() {
        let creds = Credentials::anonymous(
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
        };
        
        let cookie = NonceCookie::create(features);
        assert!(cookie.nonce.starts_with(b"obMatJos"));
        assert_eq!(cookie.nonce[8], 0x03); // bits 0 and 1 set
        
        // Test parsing
        let parsed = NonceCookie::parse(&cookie.nonce).unwrap();
        assert_eq!(parsed.features.message_integrity_sha256, true);
        assert_eq!(parsed.features.userhash, true);
        assert_eq!(parsed.features.password_algorithm, false);
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
}