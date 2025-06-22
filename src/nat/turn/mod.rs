// src/nat/turn/mod.rs
//! Basic TURN relay implementation (RFC 5766/8656).
//! NOTE: This is a simplified server for demonstration and testing.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{info, warn};
use rand::RngCore;

use crate::nat::error::{NatResult, NatError, TurnError};
use crate::nat::stun::{Message, MessageType, Attribute, AttributeType, AttributeValue, MessageClass};
use utils::build_error_response;

/// TURN relay configuration
#[derive(Debug, Clone)]
pub struct TurnRelayConfig {
    /// Address to bind the relay on
    pub bind_addr: String,
    /// Realm for long-term credentials
    pub realm: String,
    /// Map of username -> password
    pub users: HashMap<String, String>,
    /// Maximum allocation lifetime
    pub max_lifetime: Duration,

    /// Lifetime of issued NONCE values
    pub nonce_lifetime: Duration,
    /// Optional software string
    pub software: Option<String>,
}

impl Default for TurnRelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:3478".into(),
            realm: "sharp-turn".into(),
            users: HashMap::new(),
            max_lifetime: Duration::from_secs(600),
            nonce_lifetime: Duration::from_secs(600),
            software: Some("SHARP TURN".into()),
        }
    }
}

/// A TURN allocation with permissions
struct Allocation {
    client: SocketAddr,
    relay_socket: Arc<UdpSocket>,
    permissions: HashSet<IpAddr>,
    expire: Instant,
}

struct NonceEntry {
    value: Vec<u8>,
    expire: Instant,
}

enum AuthStatus {
    Ok(Vec<u8>),
    Unauthorized(Vec<u8>),
    StaleNonce(Vec<u8>),
}

/// TURN relay server
pub struct TurnRelay {
    config: TurnRelayConfig,
    socket: Arc<UdpSocket>,
    allocations: Arc<Mutex<HashMap<SocketAddr, Allocation>>>,
    nonces: Arc<Mutex<HashMap<SocketAddr, NonceEntry>>>,
}

impl TurnRelay {
    /// Create a new TURN relay
    pub async fn new(config: TurnRelayConfig) -> NatResult<Self> {
        let socket = Arc::new(UdpSocket::bind(&config.bind_addr).await?);
        info!("TURN relay listening on {}", socket.local_addr()?);
        Ok(Self {
            config,
            socket,
            allocations: Arc::new(Mutex::new(HashMap::new())),
            nonces: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Run the relay event loop
    pub async fn run(&self) -> NatResult<()> {
        let mut buf = vec![0u8; 2048];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            let data = &buf[..len];
            let raw = bytes::BytesMut::from(data);
            if let Ok(msg) = Message::decode(raw.clone()) {
                if let Err(e) = self.handle_stun(msg, src, &raw).await {
                    warn!("STUN handling failed from {}: {}", src, e);
                }
            } else {
                // Check if it's data from peer -> relay -> client
                self.forward_data(src, data).await?;
            }
        }
    }

    /// Handle incoming STUN messages
    async fn handle_stun(&self, msg: Message, src: SocketAddr, raw: &[u8]) -> NatResult<()> {
        match msg.message_type {
            MessageType::AllocateRequest => {
                self.handle_allocate(msg, src, raw).await
            }
            MessageType::RefreshRequest => {
                self.handle_refresh(msg, src, raw).await
            }
            MessageType::CreatePermissionRequest => {
                self.handle_create_permission(msg, src, raw).await
            }
            MessageType::SendIndication => {
                if let Some(attr) = msg.get_attribute(AttributeType::Data) {
                    if let AttributeValue::Raw(payload) = &attr.value {
                        if let Some(peer_attr) = msg.get_attribute(AttributeType::XorPeerAddress) {
                            if let AttributeValue::XorMappedAddress(peer) = &peer_attr.value {
                                self.send_to_peer(src, *peer, payload).await?;
                            }
                        }
                    }
                }
                Ok(())
            }
            _ => {
                warn!("Unsupported STUN type {:?}", msg.message_type);
                let err = build_error_response(&msg, 400, "Bad Request", None);
                let bytes = err.encode(None, true)?;
                self.socket.send_to(&bytes, src).await?;
                Ok(())
            }
        }
    }

    async fn handle_allocate(&self, msg: Message, src: SocketAddr, raw: &[u8]) -> NatResult<()> {
        let key = match self.authenticate(&msg, src, raw).await? {
            AuthStatus::Ok(key) => key,
            AuthStatus::Unauthorized(nonce) => {
                let mut err = build_error_response(&msg, 401, "Unauthorized", Some(nonce));
                err.add_attribute(Attribute::new(AttributeType::Realm, AttributeValue::Realm(self.config.realm.clone())));
                let bytes = err.encode(None, true)?;
                self.socket.send_to(&bytes, src).await?;
                return Ok(());
            }
            AuthStatus::StaleNonce(nonce) => {
                let mut err = build_error_response(&msg, 438, "Stale Nonce", Some(nonce));
                err.add_attribute(Attribute::new(AttributeType::Realm, AttributeValue::Realm(self.config.realm.clone())));
                let bytes = err.encode(None, true)?;
                self.socket.send_to(&bytes, src).await?;
                return Ok(());
            }
        };

        // Allocate relay socket
        let relay_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let relay_addr = relay_socket.local_addr()?;

        let allocation = Allocation {
            client: src,
            relay_socket: relay_socket.clone(),
            permissions: HashSet::new(),
            expire: Instant::now() + self.config.max_lifetime,
        };

        self.allocations.lock().await.insert(src, allocation);

        // Build success response
        let mut resp = Message::new(MessageType::AllocateResponse, msg.transaction_id);
        resp.add_attribute(Attribute::new(
            AttributeType::XorRelayedAddress,
            AttributeValue::XorRelayedAddress(relay_addr),
        ));
        resp.add_attribute(Attribute::new(
            AttributeType::Lifetime,
            AttributeValue::Raw((self.config.max_lifetime.as_secs() as u32).to_be_bytes().to_vec()),
        ));
        if let Some(ref software) = self.config.software {
            resp.add_attribute(Attribute::new(
                AttributeType::Software,
                AttributeValue::Software(software.clone()),
            ));
        }

        let bytes = resp.encode(Some(&key), true)?;
        self.socket.send_to(&bytes, src).await?;
        Ok(())
    }

    async fn handle_refresh(&self, msg: Message, src: SocketAddr, raw: &[u8]) -> NatResult<()> {
        let key = match self.authenticate(&msg, src, raw).await? {
            AuthStatus::Ok(key) => key,
            AuthStatus::Unauthorized(nonce) => {
                let mut err = build_error_response(&msg, 401, "Unauthorized", Some(nonce));
                err.add_attribute(Attribute::new(AttributeType::Realm, AttributeValue::Realm(self.config.realm.clone())));
                let bytes = err.encode(None, true)?;
                self.socket.send_to(&bytes, src).await?;
                return Ok(());
            }
            AuthStatus::StaleNonce(nonce) => {
                let mut err = build_error_response(&msg, 438, "Stale Nonce", Some(nonce));
                err.add_attribute(Attribute::new(AttributeType::Realm, AttributeValue::Realm(self.config.realm.clone())));
                let bytes = err.encode(None, true)?;
                self.socket.send_to(&bytes, src).await?;
                return Ok(());
            }
        };
        let mut allocations = self.allocations.lock().await;
        if let Some(allocation) = allocations.get_mut(&src) {
            allocation.expire = Instant::now() + self.config.max_lifetime;
            let mut resp = Message::new(MessageType::RefreshResponse, msg.transaction_id);
            resp.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw((self.config.max_lifetime.as_secs() as u32).to_be_bytes().to_vec()),
            ));
            let bytes = resp.encode(Some(&key), true)?;
            self.socket.send_to(&bytes, src).await?;
        } else {
            let err = build_error_response(&msg, 437, "Allocation Mismatch", None);
            let bytes = err.encode(None, true)?;
            self.socket.send_to(&bytes, src).await?;
        }
        Ok(())
    }

    async fn handle_create_permission(&self, msg: Message, src: SocketAddr, raw: &[u8]) -> NatResult<()> {
        let key = match self.authenticate(&msg, src, raw).await? {
            AuthStatus::Ok(key) => key,
            AuthStatus::Unauthorized(nonce) => {
                let mut err = build_error_response(&msg, 401, "Unauthorized", Some(nonce));
                err.add_attribute(Attribute::new(AttributeType::Realm, AttributeValue::Realm(self.config.realm.clone())));
                let bytes = err.encode(None, true)?;
                self.socket.send_to(&bytes, src).await?;
                return Ok(());
            }
            AuthStatus::StaleNonce(nonce) => {
                let mut err = build_error_response(&msg, 438, "Stale Nonce", Some(nonce));
                err.add_attribute(Attribute::new(AttributeType::Realm, AttributeValue::Realm(self.config.realm.clone())));
                let bytes = err.encode(None, true)?;
                self.socket.send_to(&bytes, src).await?;
                return Ok(());
            }
        };
        let mut allocations = self.allocations.lock().await;
        if let Some(allocation) = allocations.get_mut(&src) {
            for attr in msg.get_attributes(AttributeType::XorPeerAddress) {
                if let AttributeValue::XorMappedAddress(peer) = attr.value {
                    allocation.permissions.insert(peer.ip());
                }
            }
            let mut resp = Message::new(MessageType::CreatePermissionResponse, msg.transaction_id);
            let bytes = resp.encode(Some(&key), true)?;
            self.socket.send_to(&bytes, src).await?;
        } else {
            let err = build_error_response(&msg, 437, "Allocation Mismatch", None);
            let bytes = err.encode(None, true)?;
            self.socket.send_to(&bytes, src).await?;
        }
        Ok(())
    }

    async fn send_to_peer(&self, src: SocketAddr, peer: SocketAddr, payload: &[u8]) -> NatResult<()> {
        let allocations = self.allocations.lock().await;
        if let Some(allocation) = allocations.get(&src) {
            if !allocation.permissions.contains(&peer.ip()) {
                return Err(NatError::Turn(TurnError::PermissionDenied(peer)));
            }
            allocation.relay_socket.send_to(payload, peer).await?;
        }
        Ok(())
    }

    async fn forward_data(&self, src: SocketAddr, data: &[u8]) -> NatResult<()> {
        // Data from peer to client via relay
        let allocations = self.allocations.lock().await;
        for (client, alloc) in allocations.iter() {
            if alloc.relay_socket.local_addr()? == src {
                self.socket.send_to(data, *client).await?;
                break;
            }
        }
        Ok(())
    }

    async fn authenticate(&self, msg: &Message, src: SocketAddr, raw: &[u8]) -> NatResult<AuthStatus> {
        let username = match msg.get_attribute(AttributeType::Username) {
            Some(a) => match &a.value { AttributeValue::Username(u) => u.clone(), _ => return Ok(AuthStatus::Unauthorized(self.refresh_nonce(src).await)) },
            None => return Ok(AuthStatus::Unauthorized(self.refresh_nonce(src).await)),
        };

        let nonce = match msg.get_attribute(AttributeType::Nonce) {
            Some(a) => match &a.value { AttributeValue::Nonce(n) => n.clone(), _ => return Ok(AuthStatus::Unauthorized(self.refresh_nonce(src).await)) },
            None => return Ok(AuthStatus::Unauthorized(self.refresh_nonce(src).await)),
        };

        let mut nonce_store = self.nonces.lock().await;
        match nonce_store.get_mut(&src) {
            Some(entry) => {
                if entry.value != nonce || Instant::now() >= entry.expire {
                    let new = self.generate_nonce();
                    *entry = NonceEntry { value: new.clone(), expire: Instant::now() + self.config.nonce_lifetime };
                    return Ok(AuthStatus::StaleNonce(entry.value.clone()));
                }
            }
            None => {
                let new = self.generate_nonce();
                nonce_store.insert(src, NonceEntry { value: new.clone(), expire: Instant::now() + self.config.nonce_lifetime });
                return Ok(AuthStatus::Unauthorized(new));
            }
        }
        drop(nonce_store);

        let key = self.long_term_key_user(&username)?;
        if !msg.verify_integrity_sha256(&key, raw)? {
            let new = self.refresh_nonce(src).await;
            return Ok(AuthStatus::Unauthorized(new));
        }
        Ok(AuthStatus::Ok(key))
    }

    async fn refresh_nonce(&self, src: SocketAddr) -> Vec<u8> {
        let mut store = self.nonces.lock().await;
        let nonce = self.generate_nonce();
        store.insert(src, NonceEntry { value: nonce.clone(), expire: Instant::now() + self.config.nonce_lifetime });
        nonce
    }

    fn generate_nonce(&self) -> Vec<u8> {
        use rand::RngCore;
        let mut buf = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    }

    fn long_term_key_user(&self, username: &str) -> NatResult<Vec<u8>> {
        let realm = self.config.realm.clone();
        let password = self.config.users.get(username)
            .ok_or_else(|| NatError::Turn(TurnError::AllocationFailed("unknown user".into())))?;
        use md5::{Md5, Digest};
        let input = format!("{}:{}:{}", username, realm, password);
        let hash = Md5::digest(input.as_bytes());
        Ok(hash.to_vec())
    }
}

/// Helper utilities for TURN server
mod utils {
    use super::*;
    use crate::nat::stun::{Message, Attribute, AttributeType, AttributeValue, MessageClass};

    pub fn build_error_response(req: &Message, code: u16, reason: &str, nonce: Option<Vec<u8>>) -> Message {
        let mut resp = Message::new(MessageType::from_method_class(req.message_type.method(), MessageClass::ErrorResponse).unwrap(), req.transaction_id);
        resp.add_attribute(Attribute::new(
            AttributeType::ErrorCode,
            AttributeValue::ErrorCode { code, reason: reason.to_string() },
        ));
        if let Some(nonce) = nonce {
            resp.add_attribute(Attribute::new(AttributeType::Nonce, AttributeValue::Nonce(nonce)));
        }
        resp
    }
}