//! NAT Router Pools Manager
//! Заглушка для feature nat-router-pools

use anyhow::Result;

/// Router pool manager (заглушка)
#[derive(Debug, Clone)]
pub struct RouterPoolManager;

impl RouterPoolManager {
    pub fn new(
        _config: impl Into<Option<crate::connectivity::config::ConnectivityConfig>>,
    ) -> Result<Self> {
        Ok(Self)
    }
}
