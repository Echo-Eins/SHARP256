//! UPnP/IGD Manager
//! Заглушка для feature upnp-support

use anyhow::Result;

/// UPnP manager (заглушка)
#[derive(Debug, Clone)]
pub struct UpnpManager;

impl UpnpManager {
    pub fn new(
        _config: impl Into<Option<crate::connectivity::config::ConnectivityConfig>>,
    ) -> Result<Self> {
        Ok(Self)
    }
}
