pub mod protocol {
    pub mod constants;
    pub mod packet;
    pub mod ack;
}

pub mod buffer;
pub mod file;
pub mod sao;
pub mod state;
pub mod progress;
pub mod sender;
pub mod receiver;

pub mod fragmentation;
#[cfg(feature = "nat-traversal")]
pub mod nat;

#[cfg(feature = "gui")]
pub mod gui;


// Re-export основных типов
pub use sender::Sender;
pub use receiver::Receiver;
pub use protocol::constants::*;
pub use fragmentation::*;
/// Инициализация логирования
pub fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(level)))
        .init();
}

/// Версия протокола
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Получение информации о системе
pub fn system_info() -> String {
    use sysinfo::System;
    
    let mut sys = System::new_all();
    sys.refresh_all();
    
    format!(
        "SHARP-256 Protocol v{}\n\
         OS: {} {}\n\
         CPU: {} cores\n\
         Memory: {} MB available",
        VERSION,
        System::name().unwrap_or_else(|| "Unknown".to_string()),
        System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        sys.cpus().len(),
        sys.available_memory() / 1024 / 1024
    )
}