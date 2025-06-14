use eframe::egui;
use std::path::PathBuf;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::Arc;
use parking_lot::RwLock;
use crate::sender::Sender as SharpSender;

pub struct SenderApp {
    // Настройки передачи
    file_path: Option<PathBuf>,
    receiver_addr: String,
    bind_addr: String,
    use_encryption: bool,
    
    // Состояние передачи
    state: Arc<RwLock<TransferState>>,
    
    // Каналы для общения с потоком передачи
    command_tx: Option<Sender<Command>>,
    update_rx: Receiver<Update>,
    
    // UI состояние
    show_file_picker: bool,
    error_message: Option<String>,
    frag_size: Arc<RwLock<Option<usize>>>,
}

#[derive(Debug, Clone)]
enum TransferState {
    Idle,
    Connecting,
    Transferring {
        progress: f32,
        speed_mbps: f64,
        eta_seconds: u64,
        bytes_sent: u64,
        total_bytes: u64,
    },
    Completed {
        total_time_s: f64,
        average_speed_mbps: f64,
    },
    Failed(String),
}

enum Command {
    Start {
        file: PathBuf,
        receiver: SocketAddr,
        bind: SocketAddr,
        encrypt: bool,
    },
    Cancel,
}

struct Update {
    state: TransferState,
}

impl SenderApp {
    pub fn new() -> Self {
        let (update_tx, update_rx) = mpsc::channel();
        
        Self {
            file_path: None,
            receiver_addr: "192.168.1.100:5555".to_string(),
            bind_addr: "0.0.0.0:0".to_string(),
            use_encryption: false,
            state: Arc::new(RwLock::new(TransferState::Idle)),
            command_tx: None,
            update_rx,
            show_file_picker: false,
            error_message: None,
            frag_size: Arc::new(RwLock::new(None)),
        }
    }
    
    fn start_transfer(&mut self, ctx: &egui::Context) {
        if let Some(file_path) = &self.file_path {
            // Парсим адреса
            let receiver_addr = match self.receiver_addr.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(e) => {
                    self.error_message = Some(format!("Invalid receiver address: {}", e));
                    return;
                }
            };
            
            let bind_addr = match self.bind_addr.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(e) => {
                    self.error_message = Some(format!("Invalid bind address: {}", e));
                    return;
                }
            };
            
            // Создаем каналы
            let (command_tx, command_rx) = mpsc::channel();
            self.command_tx = Some(command_tx);
            
            // Запускаем передачу в отдельном потоке
            let file = file_path.clone();
            let encrypt = self.use_encryption;
            let state = self.state.clone();
            let ctx_clone = ctx.clone();

            let frag_info = self.frag_size.clone();
            
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    transfer_task(
                        file,
                        receiver_addr,
                        bind_addr,
                        encrypt,
                        state,
                        command_rx,
                        ctx_clone,
                    ).await;
                });
            });
            
            *self.state.write() = TransferState::Connecting;
        } else {
            self.error_message = Some("Please select a file".to_string());
        }
    }
    
    fn cancel_transfer(&mut self) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(Command::Cancel);
        }
    }
}

impl eframe::App for SenderApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Обновляем состояние из потока
        while let Ok(update) = self.update_rx.try_recv() {
            *self.state.write() = update.state;
        }
        
        // File picker dialog
        if self.show_file_picker {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select file to send")
                .pick_file() 
            {
                self.file_path = Some(path);
            }
            self.show_file_picker = false;
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SHARP-256 File Sender");
            ui.separator();
            
            // Настройки передачи
            ui.group(|ui| {
                ui.label("Transfer Settings");
                ui.separator();
                
                ui.horizontal(|ui| {
                    ui.label("File:");
                    if let Some(path) = &self.file_path {
                        ui.label(path.file_name().unwrap_or_default().to_string_lossy());
                        if let Ok(metadata) = std::fs::metadata(path) {
                            ui.label(format!(
                                "({:.2} MB)",
                                metadata.len() as f64 / 1024.0 / 1024.0
                            ));
                        }
                    } else {
                        ui.label("No file selected");
                    }
                    
                    if ui.button("Browse...").clicked() {
                        self.show_file_picker = true;
                    }
                });
                
                ui.horizontal(|ui| {
                    ui.label("Receiver address:");
                    ui.text_edit_singleline(&mut self.receiver_addr);
                });
                
                ui.horizontal(|ui| {
                    ui.label("Local bind address:");
                    ui.text_edit_singleline(&mut self.bind_addr);
                });
                
                ui.checkbox(&mut self.use_encryption, "Use encryption (TLS 1.3)");
            });
            
            ui.add_space(20.0);
            
            // Состояние передачи
            match &*self.state.read() {
                TransferState::Idle => {
                    ui.label("Ready to transfer");
                }
                TransferState::Connecting => {
                    ui.label("Connecting to receiver...");
                    ui.spinner();
                }
                TransferState::Transferring {
                    progress,
                    speed_mbps,
                    eta_seconds,
                    bytes_sent,
                    total_bytes,
                } => {
                    ui.label(format!(
                        "Transferring: {}/{} bytes",
                        bytes_sent, total_bytes
                    ));
                    
                    let progress_bar = egui::ProgressBar::new(*progress)
                        .text(format!("{:.1}%", progress * 100.0))
                        .animate(true);
                    ui.add(progress_bar);
                    
                    ui.horizontal(|ui| {
                        ui.label(format!("Speed: {:.2} MB/s", speed_mbps));
                        ui.separator();
                        
                        let eta_str = if *eta_seconds < 60 {
                            format!("{}s", eta_seconds)
                        } else if *eta_seconds < 3600 {
                            format!("{}m {}s", eta_seconds / 60, eta_seconds % 60)
                        } else {
                            format!("{}h {}m", eta_seconds / 3600, (eta_seconds % 3600) / 60)
                        };
                        ui.label(format!("ETA: {}", eta_str));
                    });
                }
                TransferState::Completed {
                    total_time_s,
                    average_speed_mbps,
                } => {
                    ui.colored_label(egui::Color32::GREEN, "✓ Transfer completed!");
                    ui.label(format!("Time: {:.1}s", total_time_s));
                    ui.label(format!("Average speed: {:.2} MB/s", average_speed_mbps));
                }
                TransferState::Failed(error) => {
                    ui.colored_label(egui::Color32::RED, format!("✗ Transfer failed: {}", error));
                }
            }

            if let Some(size) = *self.frag_size.read() {
                ui.label(format!("Selected payload size: {} bytes", size));
            }

            // Сообщения об ошибках
            if let Some(error) = &self.error_message {
                ui.add_space(10.0);
                ui.colored_label(egui::Color32::RED, error);
            }
            
            ui.add_space(20.0);
            
            // Кнопки управления
            ui.horizontal(|ui| {
                let current = self.state.read().clone();
                match current {
                    TransferState::Idle | TransferState::Completed { .. } | TransferState::Failed(_) => {
                        if ui.button("Start Transfer").clicked() {
                            self.error_message = None;
                            self.start_transfer(ctx);
                        }
                    }
                    TransferState::Connecting | TransferState::Transferring { .. } => {
                        if ui.button("Cancel").clicked() {
                            self.cancel_transfer();
                        }
                    }
                }
            });
        });
        
        // Обновляем UI во время передачи
        if matches!(*self.state.read(), TransferState::Transferring { .. }) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

// Асинхронная задача передачи
async fn transfer_task(
    file_path: PathBuf,
    receiver_addr: SocketAddr,
    bind_addr: SocketAddr,
    use_encryption: bool,
    frag_info: Arc<RwLock<Option<usize>>>,
    state: Arc<RwLock<TransferState>>,
    command_rx: Receiver<Command>,
    ctx: egui::Context,
) {
    // Обновляем состояние
    let update_state = |new_state: TransferState| {
        *state.write() = new_state;
        ctx.request_repaint();
    };
    
    update_state(TransferState::Connecting);
    
    // Создаем sender
    match SharpSender::new(bind_addr, receiver_addr, &file_path, use_encryption).await {
        Ok(sender) => {
            match sender.detect_fragmentation().await {
                Ok(size) => *frag_info.write() = Some(size),
                Err(e) => {
                    *frag_info.write() = None;
                    update_state(TransferState::Failed(format!(
                        "Fragmentation check failed: {}",
                        e
                    )));
                    return;
                }
            }
            // Получаем размер файла
            let file_size = match std::fs::metadata(&file_path) {
                Ok(meta) => meta.len(),
                Err(e) => {
                    update_state(TransferState::Failed(format!("Cannot read file: {}", e)));
                    return;
                }
            };
            
            // Запускаем передачу с эмуляцией прогресса
            // TODO: Интегрировать реальные callbacks из sender
            let start_time = std::time::Instant::now();
            let mut transferred = 0u64;
            
            // Эмулируем прогресс для демонстрации
            loop {
                // Проверяем отмену
                if let Ok(Command::Cancel) = command_rx.try_recv() {
                    update_state(TransferState::Failed("Cancelled by user".to_string()));
                    return;
                }
                
                // Обновляем прогресс (временная эмуляция)
                transferred = (transferred + file_size / 100).min(file_size);
                let progress = transferred as f32 / file_size as f32;
                let elapsed = start_time.elapsed().as_secs_f64();
                let speed_mbps = if elapsed > 0.0 {
                    (transferred as f64 / elapsed) / 1_048_576.0
                } else {
                    0.0
                };
                let eta_seconds = if speed_mbps > 0.0 {
                    ((file_size - transferred) as f64 / (speed_mbps * 1_048_576.0)) as u64
                } else {
                    0
                };
                
                update_state(TransferState::Transferring {
                    progress,
                    speed_mbps,
                    eta_seconds,
                    bytes_sent: transferred,
                    total_bytes: file_size,
                });
                
                if transferred >= file_size {
                    update_state(TransferState::Completed {
                        total_time_s: elapsed,
                        average_speed_mbps: speed_mbps,
                    });
                    break;
                }
                
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        Err(e) => {
            update_state(TransferState::Failed(e.to_string()));
        }
    }
}