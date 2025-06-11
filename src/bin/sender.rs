use anyhow::Result;
use clap::Parser;
use SHARP3::{init_logging, system_info, sender};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "SHARP-256 File Sender", long_about = None)]
struct Args {
    /// File to send (if not specified, GUI will be launched)
    file: Option<PathBuf>,

    /// Receiver address (IP:port)
    receiver: Option<SocketAddr>,

    /// Local bind address
    #[arg(short, long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    /// Enable encryption (TLS 1.3)
    #[arg(short, long)]
    encrypt: bool,

    /// Disable NAT traversal features
    #[arg(long)]
    no_nat: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Run without GUI (headless mode)
    #[arg(long)]
    headless: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Инициализация логирования
    init_logging(&args.log_level);

    // Выводим информацию о системе
    println!("{}", system_info());
    println!();

    // Определяем режим работы
    if args.headless || (args.file.is_some() && args.receiver.is_some()) {
        // Headless режим
        if let (Some(file), Some(receiver)) = (args.file.clone(), args.receiver) {
            // Проверяем существование файла
            if !file.exists() {
                anyhow::bail!("File not found: {:?}", file);
            }

            if file.is_dir() {
                anyhow::bail!("Cannot send directory: {:?}", file);
            }

            let file_size = std::fs::metadata(&file)?.len();
            println!("File: {:?}", file);
            println!("Size: {} bytes ({:.2} MB)", file_size, file_size as f64 / 1024.0 / 1024.0);
            println!("Receiver: {}", receiver);
            println!("Encryption: {}", if args.encrypt { "enabled" } else { "disabled" });

            #[cfg(feature = "nat-traversal")]
            {
                if !args.no_nat {
                    println!("NAT traversal: enabled (STUN/UPnP/Hole-punching)");
                } else {
                    println!("NAT traversal: disabled");
                }
            }

            println!();

            run_headless(file, receiver, args.bind, args.encrypt).await
        } else {
            anyhow::bail!("In headless mode, both file and receiver address must be specified")
        }
    } else {
        // GUI режим
        #[cfg(feature = "gui")]
        {
            gui::run_sender_gui()?;
            Ok(())
        }

        #[cfg(not(feature = "gui"))]
        {
            println!("GUI not available. Please specify file and receiver address.");
            println!("Usage: sharp-sender <file> <receiver_address>");
            anyhow::bail!("Missing required arguments for headless mode")
        }
    }
}

async fn run_headless(
    file: PathBuf,
    receiver: SocketAddr,
    bind: SocketAddr,
    encrypt: bool,
) -> Result<()> {
    println!("Starting transfer in headless mode...");

    // Создаем отправителя
    let sender = sender::Sender::new(bind, receiver, &file, encrypt).await?;

    // Показываем доступный адрес для подключения
    match sender.get_connectable_address().await {
        Ok(addr) => println!("Sender available at: {}", addr),
        Err(_) => println!("Sender listening on: {}", bind),
    }

    // Запускаем передачу
    match sender.start_transfer().await {
        Ok(()) => {
            println!("\nTransfer completed successfully!");
            Ok(())
        }
        Err(e) => {
            eprintln!("\nTransfer failed: {}", e);
            Err(e)
        }
    }
}

#[cfg(feature = "gui")]
mod gui {
    use super::*;
    use SHARP3::gui::SenderApp;

    pub fn run_sender_gui() -> Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([800.0, 600.0])
                .with_title("SHARP-256 Sender"),
            ..Default::default()
        };

        eframe::run_native(
            "SHARP-256 Sender",
            options,
            Box::new(|_cc| Box::new(SenderApp::new())),
        ).map_err(|e| anyhow::anyhow!("GUI error: {}", e))
    }
}