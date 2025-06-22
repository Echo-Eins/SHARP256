// src/nat/turn/mod.rs
//! Basic TURN relay implementation (RFC 5766/8656).
//! NOTE: This is a simplified server for demonstration and testing.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::nat::error::{NatResult, NatError, TurnError};
use crate::nat::stun::{Message, MessageType, Attribute, AttributeType, AttributeValue, MessageClass};
use utils::{check_message_integrity, build_error_response};

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

/// TURN relay server
pub struct TurnRelay {
    config: TurnRelayConfig,
    socket: Arc<UdpSocket>,
    allocations: Arc<Mutex<HashMap<SocketAddr, Allocation>>>,
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
        })
    }

    /// Run the relay event loop
    pub async fn run(&self) -> NatResult<()> {
        let mut buf = vec![0u8; 2048];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            let data = &buf[..len];
            if let Ok(msg) = Message::decode(bytes::BytesMut::from(data)) {
                if let Err(e) = self.handle_stun(msg, src).await {
                    warn!("STUN handling failed from {}: {}", src, e);
                }
            } else {
                // Check if it's data from peer -> relay -> client
                self.forward_data(src, data).await?;
            }
        }
    }

    /// Handle incoming STUN messages
    async fn handle_stun(&self, msg: Message, src: SocketAddr) -> NatResult<()> {
        match msg.message_type {
            MessageType::AllocateRequest => {
                self.handle_allocate(msg, src).await
            }
            MessageType::RefreshRequest => {
                self.handle_refresh(msg, src).await
            }
            MessageType::CreatePermissionRequest => {
                self.handle_create_permission(msg, src).await
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

    async fn handle_allocate(&self, msg: Message, src: SocketAddr) -> NatResult<()> {
        check_message_integrity(&msg, &self.config, &self.socket, src)?;

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

        let key = self.long_term_key(&msg)?;
        let bytes = resp.encode(Some(&key), true)?;
        self.socket.send_to(&bytes, src).await?;
        Ok(())
    }

    async fn handle_refresh(&self, msg: Message, src: SocketAddr) -> NatResult<()> {
        check_message_integrity(&msg, &self.config, &self.socket, src)?;
        let mut allocations = self.allocations.lock().await;
        if let Some(allocation) = allocations.get_mut(&src) {
            allocation.expire = Instant::now() + self.config.max_lifetime;
            let mut resp = Message::new(MessageType::RefreshResponse, msg.transaction_id);
            resp.add_attribute(Attribute::new(
                AttributeType::Lifetime,
                AttributeValue::Raw((self.config.max_lifetime.as_secs() as u32).to_be_bytes().to_vec()),
            ));
            let key = self.long_term_key(&msg)?;
            let bytes = resp.encode(Some(&key), true)?;
            self.socket.send_to(&bytes, src).await?;
        } else {
            let err = build_error_response(&msg, 437, "Allocation Mismatch", None);
            let bytes = err.encode(None, true)?;
            self.socket.send_to(&bytes, src).await?;
        }
        Ok(())
    }

    async fn handle_create_permission(&self, msg: Message, src: SocketAddr) -> NatResult<()> {
        check_message_integrity(&msg, &self.config, &self.socket, src)?;
        let mut allocations = self.allocations.lock().await;
        if let Some(allocation) = allocations.get_mut(&src) {
            for attr in msg.get_attributes(AttributeType::XorPeerAddress) {
                if let AttributeValue::XorMappedAddress(peer) = attr.value {
                    allocation.permissions.insert(peer.ip());
                }
            }
            let mut resp = Message::new(MessageType::CreatePermissionResponse, msg.transaction_id);
            let key = self.long_term_key(&msg)?;
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

    fn long_term_key(&self, msg: &Message) -> NatResult<Vec<u8>> {
        let username = msg
            .get_attribute(AttributeType::Username)
            .and_then(|a| match &a.value { AttributeValue::Username(u) => Some(u.clone()), _ => None })
            .ok_or_else(|| NatError::Turn(TurnError::AllocationFailed("missing username".into())))?;
        let realm = self.config.realm.clone();
        let password = self.config.users.get(&username)
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

    pub fn check_message_integrity(msg: &Message, _config: &TurnRelayConfig, _socket: &UdpSocket, _src: SocketAddr) -> NatResult<()> {
        if msg.get_attribute(AttributeType::MessageIntegrity).is_none() {
            return Err(NatError::Turn(TurnError::AllocationFailed("no integrity".into())));
        }
        // TODO: verify NONCE (not implemented)
        Ok(())
    }

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