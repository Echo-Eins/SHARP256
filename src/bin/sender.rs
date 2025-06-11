#[cfg(feature = "gui")]
mod gui {
    use super::*;
    use sharp_256::gui::SenderApp;
    
    pub fn run_sender_gui(
        file: PathBuf,
        receiver: SocketAddr,
        bind: SocketAddr,
        encrypt: bool,
    ) -> Result<()> {
        let options = eframe::NativeOptions {use anyhow::Result;
use clap::Parser;
use sharp_256::{init_logging, system_info, Sender};
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
} error)
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
    if args.headless || args.file.is_some() {
        // Headless режим
        if let (Some(file), Some(receiver)) = (args.file, args.receiver) {
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
            
            let args_copy = Args {
                file: Some(file),
                receiver: Some(receiver),
                bind: args.bind,
                encrypt: args.encrypt,
                no_nat: args.no_nat,
                log_level: args.log_level,
                headless: true,
            };
            
            run_headless(args_copy).await
        } else {
            anyhow::bail!("In headless mode, both file and receiver address must be specified")
        }
    } else {
        // GUI режим
        #[cfg(feature = "gui")]
        {
            // GUI запускается со своим интерфейсом для выбора файлов
            crate::gui::run_sender_gui()?;
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
    println!("Starting transfer in headless mode...");
    
    let file = args.file.unwrap();
    let receiver = args.receiver.unwrap();
    
    // Создаем отправителя
    let sender = Sender::new(
        args.bind,
        receiver,
        &file,
        args.encrypt,
    ).await?;
    
    // Показываем доступный адрес для подключения
    match sender.get_connectable_address().await {
        Ok(addr) => println!("Sender available at: {}", addr),
        Err(_) => println!("Sender listening on: {}", args.bind),
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
    use sharp_256::gui::SenderApp;
    
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
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([800.0, 600.0])
                .with_title("SHARP-256 Sender"),
            ..Default::default()
        };
        
        eframe::run_native(
            "SHARP-256 Sender",
            options,
            Box::new(|_cc| Box::new(SenderApp::new(file, receiver, bind, encrypt))),
        ).map_err(|e| anyhow::anyhow!("GUI error: {}", e))
    }
    
    struct SenderApp {
        file: PathBuf,
        receiver: SocketAddr,
        bind: SocketAddr,
        encrypt: bool,
        status: String,
        progress: f32,
        speed: f64,
        eta: String,
        tx: Option<mpsc::Sender<Message>>,
        rx: mpsc::Receiver<Update>,
    }
    
    enum Message {
        Start,
        Cancel,
    }
    
    struct Update {
        status: String,
        progress: f32,
        speed: f64,
        eta: String,
    }
    
    impl SenderApp {
        fn new(file: PathBuf, receiver: SocketAddr, bind: SocketAddr, encrypt: bool) -> Self {
            let (update_tx, update_rx) = mpsc::channel();
            
            Self {
                file,
                receiver,
                bind,
                encrypt,
                status: "Ready to send".to_string(),
                progress: 0.0,
                speed: 0.0,
                eta: "Unknown".to_string(),
                tx: None,
                rx: update_rx,
            }
        }
    }
    
    impl eframe::App for SenderApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            // Обновляем статус из потока передачи
            while let Ok(update) = self.rx.try_recv() {
                self.status = update.status;
                self.progress = update.progress;
                self.speed = update.speed;
                self.eta = update.eta;
            }
            
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("SHARP-256 File Sender");
                ui.separator();
                
                egui::Grid::new("info_grid")
                    .num_columns(2)
                    .spacing([40.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("File:");
                        ui.label(self.file.display().to_string());
                        ui.end_row();
                        
                        ui.label("Receiver:");
                        ui.label(self.receiver.to_string());
                        ui.end_row();
                        
                        ui.label("Encryption:");
                        ui.label(if self.encrypt { "Enabled" } else { "Disabled" });
                        ui.end_row();
                    });
                
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(20.0);
                
                ui.label(&self.status);
                ui.add_space(10.0);
                
                let progress_bar = egui::ProgressBar::new(self.progress)
                    .text(format!("{:.1}%", self.progress * 100.0));
                ui.add(progress_bar);
                
                ui.add_space(10.0);
                
                egui::Grid::new("stats_grid")
                    .num_columns(2)
                    .spacing([40.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Speed:");
                        ui.label(format!("{:.2} MB/s", self.speed));
                        ui.end_row();
                        
                        ui.label("ETA:");
                        ui.label(&self.eta);
                        ui.end_row();
                    });
                
                ui.add_space(20.0);
                
                ui.horizontal(|ui| {
                    if ui.button("Start Transfer").clicked() && self.tx.is_none() {
                        // Запускаем передачу в отдельном потоке
                        // TODO: Реализовать запуск передачи
                        self.status = "Starting transfer...".to_string();
                    }
                    
                    if ui.button("Cancel").clicked() && self.tx.is_some() {
                        if let Some(tx) = &self.tx {
                            let _ = tx.send(Message::Cancel);
                        }
                    }
                });
            });
            
            // Перерисовка каждые 100мс для обновления прогресса
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}