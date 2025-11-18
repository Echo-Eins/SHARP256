// src/connectivity/stun/integrity.rs
//! MESSAGE-INTEGRITY Implementation
//!
//! RFC 8489 Section 14.4: MESSAGE-INTEGRITY uses HMAC-SHA1
//!
//! The key for MESSAGE-INTEGRITY is:
//! - For short-term credentials: SASLprep(password)
//! - For long-term credentials: MD5(username:realm:SASLprep(password))
//!
//! For ICE, we use short-term credentials with the ICE password.

use anyhow::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::constants::ATTR_MESSAGE_INTEGRITY;

type HmacSha1 = Hmac<Sha1>;

/// Errors during MESSAGE-INTEGRITY operations
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("HMAC computation failed: {0}")]
    HmacFailed(String),

    #[error("MESSAGE-INTEGRITY verification failed")]
    VerificationFailed,

    #[error("No MESSAGE-INTEGRITY attribute in response")]
    MissingAttribute,

    #[error("Invalid key length")]
    InvalidKey,
}

/// MESSAGE-INTEGRITY calculator and verifier
pub struct MessageIntegrity {
    /// Key for HMAC-SHA1
    key: Vec<u8>,
}

impl MessageIntegrity {
    /// Create new MessageIntegrity with ICE credentials
    ///
    /// For ICE, the key is the remote ICE password (for incoming)
    /// or local ICE password (for outgoing with short-term creds).
    pub fn new(password: &str) -> Self {
        Self {
            key: password.as_bytes().to_vec(),
        }
    }

    /// Create with raw key bytes
    pub fn with_key(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Calculate MESSAGE-INTEGRITY for a STUN message
    ///
    /// The HMAC is computed over the STUN message up to and including
    /// the attribute that precedes MESSAGE-INTEGRITY, with the message
    /// length adjusted to include MESSAGE-INTEGRITY.
    ///
    /// # Arguments
    ///
    /// * `message_bytes` - Message bytes up to (but not including) MESSAGE-INTEGRITY,
    ///   with the length field adjusted to include MESSAGE-INTEGRITY (24 bytes more)
    pub fn calculate(&self, message_bytes: &[u8]) -> Result<[u8; 20], IntegrityError> {
        let mut mac = HmacSha1::new_from_slice(&self.key)
            .map_err(|e| IntegrityError::HmacFailed(e.to_string()))?;

        mac.update(message_bytes);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut hmac = [0u8; 20];
        hmac.copy_from_slice(&bytes);
        Ok(hmac)
    }

    /// Verify MESSAGE-INTEGRITY of a received STUN message
    ///
    /// # Arguments
    ///
    /// * `message` - Complete received message
    /// * `expected_hmac` - The MESSAGE-INTEGRITY value from the message
    pub fn verify(&self, message: &[u8], expected_hmac: &[u8; 20]) -> Result<(), IntegrityError> {
        // Find MESSAGE-INTEGRITY position
        let mi_pos = find_message_integrity_position(message)
            .ok_or(IntegrityError::MissingAttribute)?;

        // Create a copy with adjusted length for verification
        let mut verify_msg = message[..mi_pos].to_vec();

        // Adjust the message length in header to include MESSAGE-INTEGRITY
        // Length field is at bytes 2-3
        let current_length = u16::from_be_bytes([message[2], message[3]]);
        // The length should be up to and including MESSAGE-INTEGRITY (mi_pos - 20 + 24)
        let adjusted_length = (mi_pos - 20 + 24) as u16;
        verify_msg[2] = (adjusted_length >> 8) as u8;
        verify_msg[3] = (adjusted_length & 0xFF) as u8;

        let calculated = self.calculate(&verify_msg)?;

        // Constant-time comparison
        if constant_time_compare(&calculated, expected_hmac) {
            Ok(())
        } else {
            Err(IntegrityError::VerificationFailed)
        }
    }

    /// Add MESSAGE-INTEGRITY to a message being built
    ///
    /// Returns the complete HMAC value to be added as attribute
    pub fn sign(&self, message_without_integrity: &[u8]) -> Result<[u8; 20], IntegrityError> {
        self.calculate(message_without_integrity)
    }
}

/// Find the position of MESSAGE-INTEGRITY attribute in a message
fn find_message_integrity_position(message: &[u8]) -> Option<usize> {
    if message.len() < 20 {
        return None;
    }

    let mut pos = 20; // Start after header

    while pos + 4 <= message.len() {
        let attr_type = u16::from_be_bytes([message[pos], message[pos + 1]]);
        let attr_len = u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize;

        if attr_type == ATTR_MESSAGE_INTEGRITY {
            return Some(pos);
        }

        // Move to next attribute (4 byte header + value + padding)
        let padded_len = (attr_len + 3) & !3;
        pos += 4 + padded_len;
    }

    None
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Helper to create MESSAGE-INTEGRITY key from ICE credentials
pub fn create_ice_key(local_ufrag: &str, remote_ufrag: &str, password: &str) -> Vec<u8> {
    // For ICE connectivity checks, the key is simply the password
    // The username is "remote_ufrag:local_ufrag" but that's in USERNAME attr
    password.as_bytes().to_vec()
}

/// FINGERPRINT calculation (CRC32)
pub fn calculate_fingerprint(message: &[u8]) -> u32 {
    let crc = crc32fast::hash(message);
    crc ^ 0x5354554E // XOR with "STUN" in ASCII
}

/// Verify FINGERPRINT attribute
pub fn verify_fingerprint(message: &[u8], expected: u32) -> bool {
    // The FINGERPRINT is calculated over the message up to but not including FINGERPRINT
    // Find FINGERPRINT position (it's always the last attribute)
    if message.len() < 28 {
        return false;
    }

    // Assume FINGERPRINT is at the end (4 byte header + 4 byte value)
    let fp_start = message.len() - 8;
    let calculated = calculate_fingerprint(&message[..fp_start]);
    calculated == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_calculation() {
        let mi = MessageIntegrity::new("password");

        // Simple test message
        let message = vec![0u8; 32];
        let hmac = mi.calculate(&message).unwrap();

        // HMAC should be 20 bytes
        assert_eq!(hmac.len(), 20);
    }

    #[test]
    fn test_hmac_consistency() {
        let mi = MessageIntegrity::new("password");
        let message = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let hmac1 = mi.calculate(&message).unwrap();
        let hmac2 = mi.calculate(&message).unwrap();

        // Same message should produce same HMAC
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn test_different_keys() {
        let mi1 = MessageIntegrity::new("password1");
        let mi2 = MessageIntegrity::new("password2");

        let message = vec![1, 2, 3, 4];

        let hmac1 = mi1.calculate(&message).unwrap();
        let hmac2 = mi2.calculate(&message).unwrap();

        // Different keys should produce different HMACs
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }

    #[test]
    fn test_fingerprint() {
        let message = b"Test message for CRC32";
        let fp = calculate_fingerprint(message);

        // Fingerprint should be non-zero
        assert_ne!(fp, 0);

        // Same message should produce same fingerprint
        let fp2 = calculate_fingerprint(message);
        assert_eq!(fp, fp2);
    }

    #[test]
    fn test_ice_key_creation() {
        let key = create_ice_key("local", "remote", "secret123");
        assert_eq!(key, b"secret123");
    }
}
