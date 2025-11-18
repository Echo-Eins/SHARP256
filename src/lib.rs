//! SHARP-256 Protocol Library (lib.rs)
//!
//! High-performance file transfer protocol with BLAKE3 integrity verification
//! and comprehensive NAT traversal support.

#![warn(missing_docs)]
#![warn(clippy::all)]

// Core protocol modules
pub mod protocol;
pub mod buffer;
pub mod file;
pub mod sao;
pub mod state;
pub mod progress;
pub mod sender;
pub mod receiver;
// Fragmentation module with stub implementation
pub mod fragmentation;
<<<<<<< Updated upstream
// NAT traversal module (always compiled, feature controls functionality)
pub mod nat;
pub mod security;
// GUI module (feature-gated)
#[cfg(feature = "gui")]
pub mod gui;

// Re-export main types
pub use sender::Sender;
pub use receiver::Receiver;
pub use protocol::constants::*;
pub use progress::{ProgressInfo, TransferEvent, ProgressCallback, EventCallback};
// pub use nat::ice::*;

// Re-export fragmentation types
pub use fragmentation::{
    FragmentationInfo,
    check_fragmentation,
    detect_max_payload,
    handle_fragmentation_packet,
};

// Re-export NAT types
pub use nat::{
    NatManager,
    NatConfig,
    NetworkInfo,
    NatType,
    ConnectivityStatus,
    NatProtocol,
};

// Re-export error types
#[cfg(feature = "nat-traversal")]
pub use nat::error::{NatError, NatResult};

/// Protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize logging system with custom configuration
///
/// # Arguments
/// * `level` - Log level (trace/debug/info/warn/error)
///
/// # Example
/// ```
///SHARP3::init_logging("info");
/// ```
///
pub fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"))
        // Reduce verbosity of some dependencies
        .add_directive("igd=warn".parse().unwrap())
        .add_directive("tokio=warn".parse().unwrap())
        .add_directive("runtime=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("reqwest=warn".parse().unwrap());



// Новая connectivity система (заменяет старый nat модуль)
#[cfg(feature = "connectivity")]
pub mod connectivity;

#[cfg(feature = "gui")]
pub mod gui;

// Re-export основных типов
pub use sender::Sender;
pub use receiver::Receiver;
pub use protocol::constants::*;
pub use fragmentation::*;

// Re-export connectivity типов
#[cfg(feature = "connectivity")]
pub use connectivity::{
    Connectivity, ConnectivityManager, ConnectivityEvent,
    Candidate, CandidatePair, ConnectionState,
    EstablishedConnection, Transport, TransportType
};

/// Инициализация логирования
pub fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};


    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_ansi(true)
        )
        .with(filter)
        .init();
}

/// Get detailed system information including network interfaces
///
/// # Returns
/// A formatted string containing system and network information
pub fn system_info() -> String {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();


    let cpu_brand = sys.cpus()
        .first()
        .map(|cpu| cpu.brand())
        .unwrap_or("Unknown");

    let mut info = format!(
        "SHARP-256 Protocol v{}\n\
         ════════════════════════════════════════\n\
         OS: {} {}\n\
         CPU: {} ({} cores)\n\
         Memory: {:.2} GB available / {:.2} GB total",
        VERSION,
        System::name().unwrap_or_else(|| "Unknown".to_string()),
        System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        cpu_brand,
        sys.cpus().len(),

        sys.available_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
        sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0
    );

    // Add network interface information
    #[cfg(feature = "nat-traversal")]
    {
        info.push_str("\n\nNetwork Interfaces:");
        if let Ok(interfaces) = if_addrs::get_if_addrs() {
            let mut displayed = false;

            for iface in interfaces {
                if !iface.is_loopback() {
                    let ip_version = match iface.ip() {
                        std::net::IpAddr::V4(_) => "IPv4",
                        std::net::IpAddr::V6(_) => "IPv6",
                    };

                    info.push_str(&format!(
                        "\n  {} ({}): {}",
                        iface.name,
                        ip_version,
                        iface.ip()
                    ));
                    displayed = true;
                }
            }
            if !displayed {
                info.push_str("\n  No active network interfaces found");
            }
        } else {
            info.push_str("\n  Failed to enumerate network interfaces");
        }
    }

    info.push_str("\n════════════════════════════════════════");
    info
}

/// Builder for creating a Sender with custom configuration
pub struct SenderBuilder {
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
    file_path: std::path::PathBuf,
    use_encryption: bool,
    nat_config: Option<NatConfig>,
}

impl SenderBuilder {
    /// Create a new sender builder
    pub fn new(
        local_addr: impl Into<std::net::SocketAddr>,
        peer_addr: impl Into<std::net::SocketAddr>,
        file_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            local_addr: local_addr.into(),
            peer_addr: peer_addr.into(),
            file_path: file_path.into(),
            use_encryption: false,
            nat_config: None,
        }
    }

    /// Enable encryption
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.use_encryption = enabled;
        self
    }

    /// Set custom NAT configuration
    #[cfg(feature = "nat-traversal")]
    pub fn with_nat_config(mut self, config: NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Build the sender
    pub async fn build(self) -> anyhow::Result<Sender> {
        Sender::new(
            self.local_addr,
            self.peer_addr,
            &self.file_path,
            self.use_encryption,
        ).await
    }
}

/// Builder for creating a Receiver with custom configuration
pub struct ReceiverBuilder {
    local_addr: std::net::SocketAddr,
    output_dir: std::path::PathBuf,
    nat_config: Option<NatConfig>,
}

impl ReceiverBuilder {
    /// Create a new receiver builder
    pub fn new(
        local_addr: impl Into<std::net::SocketAddr>,
        output_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            local_addr: local_addr.into(),
            output_dir: output_dir.into(),
            nat_config: None,
        }
    }

    /// Set custom NAT configuration
    #[cfg(feature = "nat-traversal")]
    pub fn with_nat_config(mut self, config: NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Build the receiver
    pub async fn build(self) -> anyhow::Result<Receiver> {
        Receiver::new(self.local_addr, self.output_dir).await
    }
}

/// Check if the current build has NAT traversal support
pub const fn has_nat_traversal() -> bool {
    cfg!(feature = "nat-traversal")
}

/// Check if the current build has GUI support
pub const fn has_gui() -> bool {
    cfg!(feature = "gui")
}

/// Check if the current build has TLS support
pub const fn has_tls() -> bool {
    cfg!(feature = "tls")
        sys.available_memory() / 1024 / 1024);

    // Добавляем информацию о connectivity возможностях
    #[cfg(feature = "connectivity")]
    {
        info.push_str("\n\nConnectivity Features:");

        #[cfg(feature = "webrtc-ice-stack")]
        info.push_str("\n  ✓ WebRTC ICE support");

        #[cfg(feature = "libp2p-fallback")]
        info.push_str("\n  ✓ libp2p fallback");

        #[cfg(feature = "relay-encryption")]
        info.push_str("\n  ✓ Relay header encryption");

        #[cfg(feature = "nat-router-pools")]
        info.push_str("\n  ✓ NAT router pools");

        #[cfg(feature = "upnp-support")]
        info.push_str("\n  ✓ UPnP support");
    }

    #[cfg(not(feature = "connectivity"))]
    {
        info.push_str("\n\nConnectivity: Direct connections only");
    }

    info
}

/// Получение connectivity конфигурации по умолчанию
#[cfg(feature = "connectivity")]
pub fn default_connectivity_config() -> connectivity::config::ConnectivityConfig {
    connectivity::config::ConnectivityConfig::default()
}

/// Получение connectivity конфигурации для production
#[cfg(feature = "connectivity")]
pub fn production_connectivity_config() -> connectivity::config::ConnectivityConfig {
    connectivity::config::ConnectivityConfig::for_production()
}

/// Получение connectivity конфигурации оптимизированной для symmetric NAT
#[cfg(feature = "connectivity")]
pub fn symmetric_nat_connectivity_config() -> connectivity::config::ConnectivityConfig {
    let mut config = connectivity::config::ConnectivityConfig::for_production();
    config.optimize_for_symmetric_nat();
    config
}

/// Утилиты для работы с connectivity
#[cfg(feature = "connectivity")]
pub mod connectivity_utils {
    use super::connectivity::*;
    use std::net::SocketAddr;

    /// Создание connectivity с автоматической конфигурацией
    pub async fn create_auto_connectivity() -> anyhow::Result<Connectivity> {
        let config = super::default_connectivity_config();
        Connectivity::with_config(config).await
    }

    /// Создание connectivity для symmetric NAT
    pub async fn create_symmetric_nat_connectivity() -> anyhow::Result<Connectivity> {
        let config = super::symmetric_nat_connectivity_config();
        Connectivity::with_config(config).await
    }

    /// Быстрая проверка соединения между двумя адресами
    pub async fn quick_connectivity_test(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<bool> {
        use tokio::net::UdpSocket;
        use std::sync::Arc;
        use std::time::Duration;

        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        let connectivity = create_auto_connectivity().await?;

        match tokio::time::timeout(
            Duration::from_secs(10),
            connectivity.establish_connection(socket, Some(remote_addr), true)
        ).await {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Получение лучшего адреса для подключения
    pub async fn get_best_connectable_address() -> anyhow::Result<SocketAddr> {
        let connectivity = create_auto_connectivity().await?;
        connectivity.get_connectable_address().await
    }
}

/// Compatibility layer для старого NAT API
#[cfg(feature = "connectivity")]
pub mod nat_compat {
    //! Совместимость с старым NAT API для плавного перехода

    use super::connectivity::*;
    use anyhow::Result;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    /// Эмуляция старого NatManager
    pub struct NatManager {
        connectivity: Connectivity,
    }

    impl NatManager {
        /// Создание нового NAT manager (теперь использует connectivity)
        pub async fn new() -> Result<Self> {
            let connectivity = Connectivity::new().await?;
            Ok(Self { connectivity })
        }

        /// Инициализация (совместимость)
        pub async fn initialize(&self, _socket: &UdpSocket) -> Result<()> {
            // В новой системе инициализация происходит при создании соединения
            Ok(())
        }

        /// Получение connectable адреса
        pub async fn get_connectable_address(&self) -> Result<SocketAddr> {
            self.connectivity.get_connectable_address().await
        }

        /// Подготовка соединения
        pub async fn prepare_connection(
            &self,
            socket: &UdpSocket,
            peer_addr: SocketAddr,
            is_initiator: bool,
        ) -> Result<()> {
            let socket_arc = Arc::new(socket.try_clone()?);
            let _connection = self.connectivity.establish_connection(
                socket_arc,
                Some(peer_addr),
                is_initiator
            ).await?;
            Ok(())
        }

        /// Cleanup (совместимость)
        pub async fn cleanup(&self) -> Result<()> {
            self.connectivity.shutdown().await
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]

    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_system_info() {
        let info = system_info();
        assert!(info.contains("SHARP-256"));
        assert!(info.contains("OS:"));
        assert!(info.contains("CPU:"));
    }

    #[test]
    fn test_feature_detection() {
        // These should compile regardless of features
        let _ = has_nat_traversal();
        let _ = has_gui();
        let _ = has_tls();

    fn test_system_info() {
        let info = system_info();
        assert!(info.contains("SHARP-256 Protocol"));
        assert!(info.contains("CPU:"));
        assert!(info.contains("Memory:"));
    }

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.chars().next().unwrap().is_ascii_digit());
    }

    #[cfg(feature = "connectivity")]
    #[test]
    fn test_default_connectivity_config() {
        let config = default_connectivity_config();
        assert!(!config.ice.stun_servers.is_empty());
        assert!(config.general.connection_timeout.as_secs() > 0);
    }

    #[cfg(feature = "connectivity")]
    #[test]
    fn test_symmetric_nat_config() {
        let config = symmetric_nat_connectivity_config();

        // Проверяем что конфигурация оптимизирована для symmetric NAT
        assert_eq!(
            config.general.connection_methods_order[0],
            connectivity::config::ConnectionMethod::RouterPools
        );
        assert!(config.ice.candidate_priorities.relay > 0);
    }

    #[cfg(feature = "connectivity")]
    #[tokio::test]
    async fn test_connectivity_creation() {
        let connectivity = connectivity_utils::create_auto_connectivity().await;
        assert!(connectivity.is_ok());
    }

    #[cfg(feature = "connectivity")]
    #[tokio::test]
    async fn test_nat_compat_layer() {
        let nat_manager = nat_compat::NatManager::new().await;
        assert!(nat_manager.is_ok());

    }
}