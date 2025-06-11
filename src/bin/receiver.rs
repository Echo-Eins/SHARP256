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
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([800.0, 600.0])
                .with_title("SHARP-256 Receiver"),
            ..Default::default()
        };
        
        eframe::run_native(
            "SHARP-256 Receiver",
            options,
            Box::new(|_cc| Box::new(ReceiverApp::new(output, bind))),
        ).map_err(|e| anyhow::anyhow!("GUI error: {}", e))
    }
    
    struct ReceiverApp {
        output: PathBuf,
        bind: SocketAddr,
        status: String,
        current_file: Option<String>,
        progress: f32,
        speed: f64,
        transfers: Vec<TransferInfo>,
        rx: mpsc::Receiver<Update>,
    }
    
    struct TransferInfo {
        file_name: String,
        size: u64,
        sender: String,
        start_time: std::time::Instant,
        status: String,
    }
    
    struct Update {
        status: String,
        file_name: Option<String>,
        progress: f32,
        speed: f64,
    }
    
    impl ReceiverApp {
        fn new(output: PathBuf, bind: SocketAddr) -> Self {
            let (update_tx, update_rx) = mpsc::channel();
            
            // Запускаем получателя в отдельном потоке
            let output_clone = output.clone();
            let bind_clone = bind;
            
            thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let receiver = Receiver::new(bind_clone, output_clone).await.unwrap();
                    // TODO: Интегрировать обновления GUI
                    receiver.start().await.unwrap();
                });
            });
            
            Self {
                output,
                bind,
                status: "Listening for transfers...".to_string(),
                current_file: None,
                progress: 0.0,
                speed: 0.0,
                transfers: Vec::new(),
                rx: update_rx,
            }
        }
    }
    
    impl eframe::App for ReceiverApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            // Обновляем статус из потока приема
            while let Ok(update) = self.rx.try_recv() {
                self.status = update.status;
                self.current_file = update.file_name;
                self.progress = update.progress;
                self.speed = update.speed;
            }
            
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("SHARP-256 File Receiver");
                ui.separator();
                
                egui::Grid::new("info_grid")
                    .num_columns(2)
                    .spacing([40.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Output directory:");
                        ui.label(self.output.display().to_string());
                        ui.end_row();
                        
                        ui.label("Listen address:");
                        ui.label(self.bind.to_string());
                        ui.end_row();
                    });
                
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(20.0);
                
                ui.label(&self.status);
                
                if let Some(file) = &self.current_file {
                    ui.add_space(10.0);
                    ui.label(format!("Receiving: {}", file));
                    
                    let progress_bar = egui::ProgressBar::new(self.progress)
                        .text(format!("{:.1}%", self.progress * 100.0));
                    ui.add(progress_bar);
                    
                    ui.add_space(10.0);
                    ui.label(format!("Speed: {:.2} MB/s", self.speed));
                }
                
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(20.0);
                
                ui.heading("Transfer History");
                
                egui::ScrollArea::vertical()
                    .max_height(200.0)
                    .show(ui, |ui| {
                        for transfer in &self.transfers {
                            ui.group(|ui| {
                                ui.label(format!("File: {}", transfer.file_name));
                                ui.label(format!("Size: {:.2} MB", transfer.size as f64 / 1024.0 / 1024.0));
                                ui.label(format!("From: {}", transfer.sender));
                                ui.label(format!("Status: {}", transfer.status));
                            });
                            ui.add_space(5.0);
                        }
                    });
            });
            
            // Перерисовка каждые 100мс для обновления прогресса
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}