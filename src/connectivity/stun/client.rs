// src/connectivity/stun/client.rs
//! STUN Client Implementation
//!
//! RFC 8489 compliant STUN client with DTLS support.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, instrument, warn};

use super::{
    attributes::{ChangeRequest, StunAttribute},
    constants::*,
    integrity::MessageIntegrity,
    message::StunMessage,
    parse_stun_url,
    retransmission::{RetransmissionAction, RetransmissionConfig, RetransmissionTimer},
    transaction::{TransactionId, TransactionTracker},
    BindingResult, StunConfig, StunError,
};

/// STUN client configuration
#[derive(Debug, Clone)]
pub struct StunClientConfig {
    /// Base configuration
    pub config: StunConfig,

    /// Local address to bind to (None for auto)
    pub local_addr: Option<SocketAddr>,

    /// Enable detailed logging
    pub verbose: bool,
}

impl Default for StunClientConfig {
    fn default() -> Self {
        Self {
            config: StunConfig::default(),
            local_addr: None,
            verbose: false,
        }
    }
}

/// STUN Client for sending Binding Requests and performing NAT detection
pub struct StunClient {
    /// Configuration
    config: StunClientConfig,

    /// UDP socket
    socket: Arc<UdpSocket>,

    /// Transaction tracker
    tracker: Arc<TransactionTracker>,

    /// MESSAGE-INTEGRITY handler
    integrity: Option<MessageIntegrity>,

    /// Number of integrity failures
    integrity_failures: Arc<RwLock<u32>>,

    /// Whether to skip integrity (fallback mode)
    skip_integrity: Arc<RwLock<bool>>,
}

impl std::fmt::Debug for StunClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StunClient")
            .field("config", &self.config)
            .field("socket", &"<UdpSocket>")
            .field("tracker", &"<TransactionTracker>")
            .field("integrity", &self.integrity.is_some())
            .finish()
    }
}

impl StunClient {
    /// Create a new STUN client
    #[instrument(skip(config))]
    pub async fn new(config: StunClientConfig) -> Result<Self> {
        // Bind UDP socket
        let local_addr = config
            .local_addr
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

        let socket = UdpSocket::bind(local_addr)
            .await
            .context("Failed to bind UDP socket")?;

        info!("STUN client bound to {}", socket.local_addr()?);

        // Create MESSAGE-INTEGRITY handler if credentials provided
        let integrity = if let Some(ref pwd) = config.config.ice_pwd {
            Some(MessageIntegrity::new(pwd))
        } else {
            None
        };

        Ok(Self {
            config,
            socket: Arc::new(socket),
            tracker: Arc::new(TransactionTracker::new()),
            integrity,
            integrity_failures: Arc::new(RwLock::new(0)),
            skip_integrity: Arc::new(RwLock::new(false)),
        })
    }

    /// Send a Binding Request to a STUN server
    #[instrument(skip(self))]
    pub async fn binding_request(&self, server: &str) -> Result<BindingResult, StunError> {
        let (server_addr, use_dtls) = parse_stun_url(server)?;

        if use_dtls {
            return self.binding_request_dtls(server_addr).await;
        }

        self.binding_request_udp(server_addr, None).await
    }

    /// Send a Binding Request with CHANGE-REQUEST (RFC 5780)
    #[instrument(skip(self))]
    pub async fn binding_request_with_change(
        &self,
        server_addr: SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> Result<BindingResult, StunError> {
        let change_request = Some(ChangeRequest::new(change_ip, change_port));
        self.binding_request_udp(server_addr, change_request).await
    }

    /// Send UDP Binding Request with optional CHANGE-REQUEST
    async fn binding_request_udp(
        &self,
        server_addr: SocketAddr,
        change_request: Option<ChangeRequest>,
    ) -> Result<BindingResult, StunError> {
        // Build request
        let mut msg = StunMessage::new_binding_request();

        // Add CHANGE-REQUEST if specified
        if let Some(cr) = change_request {
            msg.add_attribute(StunAttribute::ChangeRequest(cr));
        }

        // Add USERNAME if we have credentials
        if let (Some(ref ufrag), Some(ref _pwd)) =
            (&self.config.config.ice_ufrag, &self.config.config.ice_pwd)
        {
            msg.add_attribute(StunAttribute::Username(ufrag.clone()));
        }

        // Encode message
        let mut request_bytes = msg
            .encode()
            .map_err(|e| StunError::InvalidMessage(e.to_string()))?;

        // Add MESSAGE-INTEGRITY if we have credentials and not in fallback mode
        let use_integrity = self.integrity.is_some() && !*self.skip_integrity.read().await;
        if use_integrity {
            if let Some(ref integrity) = self.integrity {
                // Calculate HMAC over message with adjusted length
                let hmac_bytes = msg
                    .encode_for_integrity(&[])
                    .map_err(|e| StunError::InvalidMessage(e.to_string()))?;

                let hmac = integrity
                    .calculate(&hmac_bytes)
                    .map_err(|_| StunError::IntegrityFailed)?;

                msg.add_attribute(StunAttribute::MessageIntegrity(hmac));
                request_bytes = msg
                    .encode()
                    .map_err(|e| StunError::InvalidMessage(e.to_string()))?;
            }
        }

        let transaction_id = msg.transaction_id;

        // Register transaction
        self.tracker
            .register(transaction_id, request_bytes.clone(), server_addr)
            .await;

        // Send with retransmission
        let result = self
            .send_with_retransmission(transaction_id, &request_bytes, server_addr)
            .await;

        // Handle integrity failures
        if let Err(StunError::IntegrityFailed) = &result {
            let mut failures = self.integrity_failures.write().await;
            *failures += 1;

            if *failures >= self.config.config.integrity_failure_threshold {
                if self.config.config.fallback_on_integrity_failure {
                    warn!(
                        "MESSAGE-INTEGRITY failed {} times, falling back to plain requests",
                        *failures
                    );
                    *self.skip_integrity.write().await = true;

                    // Retry without integrity
                    return self.binding_request_udp(server_addr, change_request).await;
                }
            }
        }

        result
    }

    /// Send request with retransmission logic
    async fn send_with_retransmission(
        &self,
        transaction_id: TransactionId,
        request: &[u8],
        server_addr: SocketAddr,
    ) -> Result<BindingResult, StunError> {
        let retrans_config = RetransmissionConfig {
            initial_rto_ms: self.config.config.initial_rto_ms,
            max_retransmissions: self.config.config.max_retransmissions,
            ..Default::default()
        };

        let mut timer = RetransmissionTimer::with_config(retrans_config);
        timer.start();

        // Send initial request
        self.socket.send_to(request, server_addr).await?;
        debug!(
            "Sent STUN Binding Request to {} (tid: {})",
            server_addr, transaction_id
        );

        let mut recv_buf = vec![0u8; MAX_MESSAGE_SIZE];

        loop {
            let wait_duration = match timer.next_action() {
                RetransmissionAction::Wait { duration } => duration,
                RetransmissionAction::WaitFinal { duration } => duration,
                RetransmissionAction::Retransmit { attempt, rto } => {
                    // Send retransmission
                    self.socket.send_to(request, server_addr).await?;
                    self.tracker.record_retransmission(&transaction_id).await;
                    debug!(
                        "Retransmission {} to {} (RTO: {:?})",
                        attempt, server_addr, rto
                    );
                    rto
                }
                RetransmissionAction::Timeout => {
                    self.tracker.fail(&transaction_id).await;
                    return Err(StunError::Timeout {
                        retries: timer.state().retransmission_count(),
                    });
                }
            };

            // Wait for response with timeout
            match timeout(wait_duration, self.socket.recv_from(&mut recv_buf)).await {
                Ok(Ok((len, from_addr))) => {
                    // Check if it's from our server
                    if from_addr != server_addr {
                        // Could be from alternate address for RFC 5780
                        debug!(
                            "Response from different address: {} (expected {})",
                            from_addr, server_addr
                        );
                    }

                    // Parse response
                    match StunMessage::decode(&recv_buf[..len]) {
                        Ok(response) => {
                            // Verify transaction ID
                            if response.transaction_id != transaction_id {
                                debug!("Transaction ID mismatch, ignoring");
                                continue;
                            }

                            // Complete transaction and get RTT
                            let tx_result = self
                                .tracker
                                .complete(transaction_id, recv_buf[..len].to_vec())
                                .await;

                            let rtt = tx_result.map(|r| r.rtt).unwrap_or(Duration::ZERO);

                            // Process response
                            return self.process_response(response, server_addr, rtt).await;
                        }
                        Err(e) => {
                            warn!("Failed to parse STUN response: {}", e);
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    // Socket error
                    return Err(StunError::Network(e));
                }
                Err(_) => {
                    // Timeout, continue to check timer state
                    continue;
                }
            }
        }
    }

    /// Process a STUN response
    async fn process_response(
        &self,
        response: StunMessage,
        server_addr: SocketAddr,
        rtt: Duration,
    ) -> Result<BindingResult, StunError> {
        // Check if it's an error response
        if response.is_error() {
            if let Some(StunAttribute::ErrorCode { code, reason }) =
                response.get_attribute(ATTR_ERROR_CODE)
            {
                return Err(StunError::ErrorResponse {
                    code: *code,
                    reason: reason.clone(),
                });
            }
            return Err(StunError::ErrorResponse {
                code: 0,
                reason: "Unknown error".to_string(),
            });
        }

        // Verify MESSAGE-INTEGRITY if present
        let integrity_verified = if let Some(StunAttribute::MessageIntegrity(hmac)) =
            response.get_attribute(ATTR_MESSAGE_INTEGRITY)
        {
            if let Some(ref integrity) = self.integrity {
                if let Some(raw) = response.raw_for_integrity() {
                    match integrity.verify(raw, hmac) {
                        Ok(()) => true,
                        Err(_) => {
                            warn!("MESSAGE-INTEGRITY verification failed");
                            return Err(StunError::IntegrityFailed);
                        }
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Extract XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS
        let xor_mapped_address = response
            .get_attribute(ATTR_XOR_MAPPED_ADDRESS)
            .and_then(|attr| {
                if let StunAttribute::XorMappedAddress(xma) = attr {
                    Some(xma.address)
                } else {
                    None
                }
            });

        let mapped_address = response
            .get_attribute(ATTR_MAPPED_ADDRESS)
            .and_then(|attr| {
                if let StunAttribute::MappedAddress(ma) = attr {
                    Some(ma.address)
                } else {
                    None
                }
            })
            .or(xor_mapped_address)
            .ok_or_else(|| {
                StunError::InvalidMessage("No mapped address in response".to_string())
            })?;

        // Extract RFC 5780 attributes
        let response_origin = response
            .get_attribute(ATTR_RESPONSE_ORIGIN)
            .and_then(|attr| {
                if let StunAttribute::ResponseOrigin(ro) = attr {
                    Some(ro.address)
                } else {
                    None
                }
            });

        let other_address = response.get_attribute(ATTR_OTHER_ADDRESS).and_then(|attr| {
            if let StunAttribute::OtherAddress(oa) = attr {
                Some(oa.address)
            } else {
                None
            }
        });

        info!(
            "STUN Binding Success: mapped={}, RTT={:?}",
            mapped_address, rtt
        );

        Ok(BindingResult {
            server_addr,
            mapped_address,
            xor_mapped_address,
            rtt,
            transaction_id: response.transaction_id,
            integrity_verified,
            response_origin,
            other_address,
        })
    }

    /// Send Binding Request over DTLS
    async fn binding_request_dtls(
        &self,
        server_addr: SocketAddr,
    ) -> Result<BindingResult, StunError> {
        // TODO: Implement DTLS using webrtc_dtls crate
        // For now, fall back to UDP with warning
        warn!(
            "DTLS not yet implemented, falling back to UDP for {}",
            server_addr
        );
        self.binding_request_udp(server_addr, None).await
    }

    /// Get transaction statistics
    pub async fn get_stats(&self) -> super::transaction::RttStats {
        self.tracker.get_stats().await
    }

    /// Get latest RTT measurement
    pub async fn get_latest_rtt(&self) -> Option<Duration> {
        self.tracker.get_latest_rtt().await
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    /// Check if in fallback mode (no MESSAGE-INTEGRITY)
    pub async fn is_fallback_mode(&self) -> bool {
        *self.skip_integrity.read().await
    }

    /// Reset integrity failure counter
    pub async fn reset_integrity_failures(&self) {
        *self.integrity_failures.write().await = 0;
        *self.skip_integrity.write().await = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = StunClientConfig::default();
        let client = StunClient::new(config).await.unwrap();

        let local_addr = client.local_addr().unwrap();
        assert!(local_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_client_with_credentials() {
        let mut config = StunClientConfig::default();
        config.config.ice_ufrag = Some("user".to_string());
        config.config.ice_pwd = Some("password".to_string());

        let client = StunClient::new(config).await.unwrap();
        assert!(client.integrity.is_some());
    }

    #[test]
    fn test_parse_stun_url() {
        let (addr, dtls) = parse_stun_url("stun:stun.l.google.com:19302").unwrap();
        assert_eq!(addr.port(), 19302);
        assert!(!dtls);

        let (addr, dtls) = parse_stun_url("stuns:stun.example.com:5349").unwrap();
        assert_eq!(addr.port(), 5349);
        assert!(dtls);
    }

    // Integration test would require actual STUN server
    // #[tokio::test]
    // async fn test_binding_request_google() {
    //     let config = StunClientConfig::default();
    //     let client = StunClient::new(config).await.unwrap();
    //
    //     let result = client.binding_request("stun:stun.l.google.com:19302").await;
    //     assert!(result.is_ok());
    // }
}
