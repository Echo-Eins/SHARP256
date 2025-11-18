//! libp2p Fallback System
//! Заглушка для feature libp2p-fallback

use anyhow::Result;
use std::net::SocketAddr;

/// libp2p client (заглушка)
#[derive(Debug, Clone)]
pub struct LibP2pClient;

impl LibP2pClient {
    pub fn new(_config: impl Into<Option<crate::connectivity::config::ConnectivityConfig>>) -> Result<Self> {
        Ok(Self)
    }

    pub async fn connect(&self, _peer: SocketAddr) -> Result<()> {
        Ok(())
    }
}
