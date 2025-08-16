use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{RwLock, oneshot};
use tokio::time::timeout;

use bytes::BytesMut;

use crate::nat::error::{NatError, NatResult};
use crate::nat::stun::{
    Message, MessageType, TransactionId, Attribute, AttributeType, AttributeValue,
};
use crate::nat::stun::{compute_message_integrity_sha256};
use crate::nat::turn::server::TurnServerConfig;


/// Manages STUN and TURN message transactions on a single socket.
///
/// This manager correlates requests and responses using the STUN
/// transaction ID and exposes helpers for common STUN and TURN
/// operations. It is designed to be shared between the ICE layer and
/// the TURN server implementation.
pub struct StunTurnMessageManager {
    socket: Arc<UdpSocket>,
    transactions: Arc<RwLock<HashMap<TransactionId, oneshot::Sender<Message>>>>,
}

impl StunTurnMessageManager {
    /// Bind a new manager to the given local address. A background
    /// task is spawned to dispatch incoming packets to the waiting
    /// transactions.
    pub async fn bind(bind_addr: SocketAddr) -> NatResult<Self> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        Self::spawn_receiver(socket.clone(), transactions.clone());
        Ok(Self { socket, transactions })
    }

    fn spawn_receiver(socket: Arc<UdpSocket>, transactions: Arc<RwLock<HashMap<TransactionId, oneshot::Sender<Message>>>>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; crate::nat::stun::MAX_MESSAGE_SIZE];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, _from)) => {
                        if let Ok(msg) = Message::decode(BytesMut::from(&buf[..size])) {
                            if let Some(tx) = transactions.write().await.remove(&msg.transaction_id) {
                                let _ = tx.send(msg);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("STUN/TURN receive error: {}", e);
                    }
                }
            }
        });
    }

    /// Send a STUN/TURN request and wait for the matching response.
    pub async fn send_request(
        &self,
        addr: SocketAddr,
        message: Message,
        integrity_key: Option<&[u8]>,
        timeout_ms: u64,
    ) -> NatResult<Message> {
        let tid = message.transaction_id;
        let encoded = message.encode(integrity_key, true)?;
        let (tx, rx) = oneshot::channel();
        self.transactions.write().await.insert(tid, tx);
        self.socket.send_to(&encoded, addr).await?;
        match timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(NatError::Platform("Response channel closed".into())),
            Err(_) => {
                self.transactions.write().await.remove(&tid);
                Err(NatError::Timeout(Duration::from_millis(timeout_ms)))
            }
        }
    }

    /// Perform a simple STUN binding request. Returns the mapped address
    /// reported by the server.
    pub async fn binding_request(&self, server: SocketAddr) -> NatResult<SocketAddr> {
        let tid = TransactionId::new();
        let request = Message::new(MessageType::BindingRequest, tid);
        let response = self
            .send_request(server, request, None, 5000)
            .await?;

        if let Some(attr) = response.get_attribute(AttributeType::XorMappedAddress) {
            if let AttributeValue::XorMappedAddress(addr) = attr.value {
                return Ok(addr);
            }
        }
        if let Some(attr) = response.get_attribute(AttributeType::MappedAddress) {
            if let AttributeValue::MappedAddress(addr) = attr.value {
                return Ok(addr);
            }
        }
        Err(NatError::Stun(crate::nat::error::StunError::MissingAttribute(
            "MAPPED-ADDRESS".into(),
        )))
    }

    /// Allocate a relay on the given TURN server using long-term credentials.
    pub async fn allocate_relay(&self, server: &TurnServerConfig) -> NatResult<SocketAddr> {
        let tid = TransactionId::new();
        let mut request = Message::new(MessageType::AllocateRequest, tid);
        request.add_attribute(Attribute::new(
            AttributeType::RequestedTransport,
            AttributeValue::RequestedTransport(17),
        ));
        request.add_attribute(Attribute::new(
            AttributeType::Username,
            AttributeValue::Username(server.realm.clone()),
        ));

        let key = compute_message_integrity_sha256(b"dummy", b"dummy")?; // placeholder
        let response = self
            .send_request(server.bind_addr, request, Some(&key), 5000)
            .await?;

        if response.message_type == MessageType::AllocateResponse
            || response.message_type == MessageType::AllocateSuccessResponse
        {
            if let Some(attr) = response.get_attribute(AttributeType::XorRelayedAddress) {
                if let AttributeValue::XorRelayedAddress(addr) = attr.value {
                    return Ok(addr);
                }
            }
        }
        Err(NatError::Turn(crate::nat::error::TurnError::AllocationFailed(
            "No relay address".into(),
        )))
    }
}
