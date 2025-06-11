use eframe::egui;
use std::path::PathBuf;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::Arc;
use parking_lot::RwLock;
use crate::receiver::Receiver as SharpReceiver;

pub struct ReceiverApp {
    // Настройки
    output_dir: PathBuf,
    bind_addr: String,
    
    // Состояние
    state: Arc<RwLock<ReceiverState>>,
    transfers: Arc<RwLock<Vec<TransferInfo>>>,
    
    // Каналы
    command_tx: Option<Sender<Command>>,
    update_rx: Receiver<Update>,
    
    // UI
    show_dir_picker: bool,
    show_incoming_dialog: Arc<RwLock<Option<IncomingTransfer>>>,
}

#[derive(Debug, Clone)]
enum ReceiverState {
    Listening(SocketAddr),
    Receiving {
        from: SocketAddr,
        file_name: String,
        progress: f32,
        speed_mbps: f64,
        bytes_received: u64,
        total_bytes: u64,
    },
}

#[derive(Debug, Clone)]
struct TransferInfo {
    file_name: String,
    size: u64,
    from: SocketAddr,
    completed: bool,
    start_time: std::time::Instant,
    end_time: Option<std::time::Instant>,
}

#[derive(Debug, Clone)]
struct IncomingTransfer {
    from: SocketAddr,
    file_name: String,
    file_size: u64,
}

enum Command {
    AcceptTransfer,
    RejectTransfer,
    ChangeOutputDir(()),
}

struct Update {
    state: Option<ReceiverState>,
    new_transfer: Option<TransferInfo>,
    incoming: Option<IncomingTransfer>,
}

impl ReceiverApp {
    pub fn new() -> Self {
        let (update_tx, update_rx) = mpsc::channel();
        let output_dir = dirs::download_dir()
            .unwrap_or_else(|| PathBuf::from("./received"));
        
        let state = Arc::new(RwLock::new(ReceiverState::Listening("0.0.0.0:5555".parse().unwrap())));
        let transfers = Arc::new(RwLock::new(Vec::new()));
        let show_incoming = Arc::new(RwLock::new(None));
        
        // Запускаем receiver в фоне
        let (command_tx, command_rx) = mpsc::channel();
        
        let state_clone = state.clone();
        let transfers_clone = transfers.clone();
        let output_dir_clone = output_dir.clone();
        let incoming_clone = show_incoming.clone();
        
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                receiver_task(
                    output_dir_clone,
                    "0.0.0.0:5555".parse().unwrap(),
                    state_clone,
                    transfers_clone,
                    incoming_clone,
                    update_tx,
                    command_rx,
                ).await;
            });
        });
        
        Self {
            output_dir,
            bind_addr: "0.0.0.0:5555".to_string(),
            state,
            transfers,
            command_tx: Some(command_tx),
            update_rx,
            show_dir_picker: false,
            show_incoming_dialog: show_incoming,
        }
    }
}

impl eframe::App for ReceiverApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Обновляем состояние
        while let Ok(update) = self.update_rx.try_recv() {
            if let Some(state) = update.state {
                *self.state.write() = state;
            }
            if let Some(transfer) = update.new_transfer {
                self.transfers.write().push(transfer);
            }
            if let Some(incoming) = update.incoming {
                *self.show_incoming_dialog.write() = Some(incoming);
            }
        }
        
        // Directory picker
        if self.show_dir_picker {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select output directory")
                .pick_folder()
            {
                self.output_dir = path.clone();
                if let Some(tx) = &self.command_tx {
                    let _ = tx.send(Command::ChangeOutputDir(path));
                }
            }
            self.show_dir_picker = false;
        }
        
        // Incoming transfer dialog
        let mut accept_transfer = false;
        let mut reject_transfer = false;
        
        if let Some(incoming) = &*self.show_incoming_dialog.read() {
            egui::Window::new("Incoming Transfer")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("Incoming transfer from: {}", incoming.from));
                    ui.label(format!("File: {}", incoming.file_name));
                    ui.label(format!("Size: {:.2} MB", incoming.file_size as f64 / 1024.0 / 1024.0));
                    
                    ui.separator();
                    
                    ui.horizontal(|ui| {
                        if ui.button("Accept").clicked() {
                            accept_transfer = true;
                        }
                        if ui.button("Reject").clicked() {
                            reject_transfer = true;
                        }
                    });
                });
        }
        
        if accept_transfer {
            if let Some(tx) = &self.command_tx {
                let _ = tx.send(Command::AcceptTransfer);
            }
            *self.show_incoming_dialog.write() = None;
        }
        
        if reject_transfer {
            if let Some(tx) = &self.command_tx {
                let _ = tx.send(Command::RejectTransfer);
            }
            *self.show_incoming_dialog.write() = None;
        }
        
        // Main UI
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SHARP-256 File Receiver");
            ui.separator();
            
            // Settings
            ui.group(|ui| {
                ui.label("Receiver Settings");
                ui.separator();
                
                ui.horizontal(|ui| {
                    ui.label("Output directory:");
                    ui.label(self.output_dir.display().to_string());
                    if ui.button("Change...").clicked() {
                        self.show_dir_picker = true;
                    }
                });
                
                ui.horizontal(|ui| {
                    ui.label("Listen address:");
                    ui.label(&self.bind_addr);
                });
                
                // Показываем публичный адрес если доступен
                #[cfg(feature = "nat-traversal")]
                {
                    ui.label("External address: Detecting...");
                }
            });
            
            ui.add_space(20.0);
            
            // Current state
            match &*self.state.read() {
                ReceiverState::Listening(addr) => {
                    ui.label(format!("Listening on {}", addr));
                    ui.label("Waiting for incoming transfers...");
                }
                ReceiverState::Receiving { from, file_name, progress, speed_mbps, bytes_received, total_bytes } => {
                    ui.label(format!("Receiving from {}", from));
                    ui.label(format!("File: {}", file_name));
                    ui.label(format!("{}/{} bytes", bytes_received, total_bytes));
                    
                    let progress_bar = egui::ProgressBar::new(*progress)
                        .text(format!("{:.1}%", progress * 100.0))
                        .animate(true);
                    ui.add(progress_bar);
                    
                    ui.label(format!("Speed: {:.2} MB/s", speed_mbps));
                }
            }
            
            ui.add_space(20.0);
            ui.separator();
            ui.add_space(10.0);
            
            // Transfer history
            ui.heading("Transfer History");
            
            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    let transfers = self.transfers.read();
                    if transfers.is_empty() {
                        ui.label("No transfers yet");
                    } else {
                        for transfer in transfers.iter().rev() {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    if transfer.completed {
                                        ui.colored_label(egui::Color32::GREEN, "✓");
                                    } else {
                                        ui.spinner();
                                    }
                                    ui.label(&transfer.file_name);
                                });
                                
                                ui.label(format!("From: {}", transfer.from));
                                ui.label(format!("Size: {:.2} MB", transfer.size as f64 / 1024.0 / 1024.0));
                                
                                if let Some(end_time) = transfer.end_time {
                                    let duration = end_time.duration_since(transfer.start_time);
                                    ui.label(format!("Time: {:.1}s", duration.as_secs_f64()));
                                }
                            });
                            ui.add_space(5.0);
                        }
                    }
                });
        });
        
        // Постоянное обновление UI
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
    }
}

// Асинхронная задача получателя
async fn receiver_task(
    output_dir: PathBuf,
    bind_addr: SocketAddr,
    state: Arc<RwLock<ReceiverState>>,
    transfers: Arc<RwLock<Vec<TransferInfo>>>,
    incoming_dialog: Arc<RwLock<Option<IncomingTransfer>>>,
    update_tx: Sender<Update>,
    command_rx: Receiver<Command>,
) {
    match SharpReceiver::new(bind_addr, output_dir).await {
        Ok(receiver) => {
            // TODO: Интегрировать колбэки прогресса
            match receiver.start().await {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!("Receiver error: {}", e);
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to create receiver: {}", e);
        }
    }
}