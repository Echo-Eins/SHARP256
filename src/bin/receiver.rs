use anyhow::Result;
use clap::Parser;
use sharp_256::{init_logging, system_info, Receiver};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "SHARP-256 File Receiver", long_about = None)]
struct Args {
    /// Directory to save received files
    #[arg(short, long, default_value = "./received")]
    output: PathBuf,

    /// Listen address (IP:port)
    #[arg(short, long, default_value = "0.0.0.0:5555")]
    bind: SocketAddr,

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

    // Создаем директорию для приема файлов
    std::fs::create_dir_all(&args.output)?;

    println!("Output directory: {:?}", args.output.canonicalize()?);
    println!("Listen address: {}", args.bind);

    #[cfg(feature = "nat-traversal")]
    {
        if !args.no_nat {
            println!("NAT traversal: enabled (STUN/UPnP/Hole-punching)");
        } else {
            println!("NAT traversal: disabled");
        }
    }

    println!();

    if args.headless {
        // Headless режим
        run_headless(args).await
    } else {
        // GUI режим
        #[cfg(feature = "gui")]
        {
            crate::gui::run_receiver_gui(args.output, args.bind)?;
            Ok(())
        }

        #[cfg(not(feature = "gui"))]
        {
            println!("GUI not available. Running in headless mode.");
            run_headless(args).await
        }
    }
}

async fn run_headless(args: Args) -> Result<()> {
    println!("Starting receiver in headless mode...");
    println!("Waiting for incoming transfers...\n");

    // Создаем получателя
    let receiver = Receiver::new(args.bind, args.output).await?;

    // Запускаем прием
    receiver.start().await
}

#[cfg(feature = "gui")]
mod gui {
    use super::*;
    use sharp_256::gui::ReceiverApp;

    pub fn run_receiver_gui(output: PathBuf, bind: SocketAddr) -> Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([800.0, 600.0])
                .with_title("SHARP-256 Receiver"),
            ..Default::default()
        };

        eframe::run_native(
            "SHARP-256 Receiver",
            options,
            Box::new(|_cc| Box::new(ReceiverApp::new())),
        ).map_err(|e| anyhow::anyhow!("GUI error: {}", e))
    }
}