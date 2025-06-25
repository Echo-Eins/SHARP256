#[derive(Debug, Clone, Copy)]
pub enum EncryptionAlgorithm {
    ChaCha20Poly1305,
    Aes256Gcm,
    Aes128Gcm,
}

pub trait CryptoProvider: Send + Sync {}

#[derive(Debug, Clone)]
pub struct KeyExchangeResult {
    pub shared_secret: [u8; 32],
}