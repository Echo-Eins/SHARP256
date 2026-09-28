use crate::config::SenderConfig;
use crate::progress::{format_bytes, format_rate, TransferEvent, TransferStats};
use crate::transport::Sender;
use eframe::egui;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
enum State {
    Idle,
    Connecting,
    Transferring(TransferStats),
    Completed { stats: TransferStats, hash: String },
    Failed(String),
}

pub struct SenderApp {
    file_path: Option<PathBuf>,
    receiver_addr: String,
    bind_addr: String,
    max_rate: String,
    state: Arc<Mutex<State>>,
    cancel: Option<CancellationToken>,
    error: Option<String>,
    pick_file: bool,
}

impl SenderApp {
    pub fn new(file: Option<PathBuf>, receiver: Option<SocketAddr>) -> Self {
        Self {
            file_path: file,
            receiver_addr: receiver
                .map(|a| a.to_string())
                .unwrap_or_else(|| "192.168.1.100:5555".to_string()),
            bind_addr: "0.0.0.0:0".to_string(),
            max_rate: String::new(),
            state: Arc::new(Mutex::new(State::Idle)),
            cancel: None,
            error: None,
            pick_file: false,
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Some(file) = self.file_path.clone() else {
            self.error = Some("Select a file first".into());
            return;
        };
        let receiver: SocketAddr = match self.receiver_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                self.error = Some(format!("Invalid receiver address: {}", e));
                return;
            }
        };
        let bind: SocketAddr = match self.bind_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                self.error = Some(format!("Invalid bind address: {}", e));
                return;
            }
        };
        let mut cfg = SenderConfig::new(receiver, file);
        cfg.bind = bind;
        if !self.max_rate.trim().is_empty() {
            match crate::progress::parse_rate(&self.max_rate) {
                Ok(bps) => cfg.transport.max_rate_bytes = Some(bps / 8),
                Err(e) => {
                    self.error = Some(e);
                    return;
                }
            }
        }
        let state = self.state.clone();
        let repaint = ctx.clone();
        cfg.events = Some(Arc::new(move |ev: TransferEvent| {
            let mut st = state.lock();
            match ev {
                TransferEvent::Started { .. } => *st = State::Connecting,
                TransferEvent::Progress(s) => *st = State::Transferring(s),
                TransferEvent::Completed {
                    stats,
                    file_hash_hex,
                    ..
                } => {
                    *st = State::Completed {
                        stats,
                        hash: file_hash_hex,
                    }
                }
                TransferEvent::Failed { error, .. } => *st = State::Failed(error),
                _ => {}
            }
            repaint.request_repaint();
        }));

        *self.state.lock() = State::Connecting;
        let state = self.state.clone();
        let cancel = CancellationToken::new();
        self.cancel = Some(cancel.clone());
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    *state.lock() = State::Failed(format!("runtime: {}", e));
                    return;
                }
            };
            rt.block_on(async move {
                let result = match Sender::new(cfg).await {
                    Ok(sender) => {
                        let token = sender.cancel_token();
                        tokio::spawn(async move {
                            cancel.cancelled().await;
                            token.cancel();
                        });
                        sender.run().await.map(|_| ())
                    }
                    Err(e) => Err(e),
                };
                if let Err(e) = result {
                    *state.lock() = State::Failed(e.to_string());
                }
                repaint.request_repaint();
            });
        });
    }
}

impl eframe::App for SenderApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.pick_file {
            self.pick_file = false;
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select file to send")
                .pick_file()
            {
                self.file_path = Some(path);
            }
        }

        let state = self.state.lock().clone();
        let busy = matches!(state, State::Connecting | State::Transferring(_));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SHARP-256 File Sender");
            ui.separator();
            ui.add_enabled_ui(!busy, |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("File:");
                        match &self.file_path {
                            Some(p) => {
                                ui.label(
                                    p.file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_default(),
                                );
                                if let Ok(m) = std::fs::metadata(p) {
                                    ui.label(format!("({})", format_bytes(m.len())));
                                }
                            }
                            None => {
                                ui.label("none selected");
                            }
                        }
                        if ui.button("Browse...").clicked() {
                            self.pick_file = true;
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
                    ui.horizontal(|ui| {
                        ui.label("Rate cap (e.g. 50M, empty = none):");
                        ui.text_edit_singleline(&mut self.max_rate);
                    });
                });
            });
            ui.add_space(12.0);

            match &state {
                State::Idle => {
                    ui.label("Ready.");
                }
                State::Connecting => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Connecting to receiver...");
                    });
                }
                State::Transferring(s) => {
                    ui.add(
                        egui::ProgressBar::new(s.fraction())
                            .text(format!("{:.1}%", s.fraction() * 100.0))
                            .animate(true),
                    );
                    ui.label(format!(
                        "{} of {}  |  {}  |  rtt {:.2} ms  |  cwnd {}  |  retransmitted {}{}",
                        format_bytes(s.bytes_done),
                        format_bytes(s.total_bytes),
                        format_rate(s.rate_bps),
                        s.rtt_ms,
                        format_bytes(s.cwnd_bytes),
                        format_bytes(s.retransmitted_bytes),
                        if s.stalled {
                            "  [stalled: waiting for receiver]"
                        } else {
                            ""
                        }
                    ));
                    if let Some(eta) = s.eta {
                        ui.label(format!("ETA {} s", eta.as_secs()));
                    }
                }
                State::Completed { stats, hash } => {
                    ui.colored_label(egui::Color32::GREEN, "Transfer completed and verified");
                    ui.label(format!(
                        "{} in {:.1} s ({} average)",
                        format_bytes(stats.total_bytes),
                        stats.elapsed.as_secs_f64(),
                        format_rate(stats.avg_rate_bps)
                    ));
                    ui.label(format!("BLAKE3: {}", hash));
                }
                State::Failed(err) => {
                    ui.colored_label(egui::Color32::RED, format!("Transfer failed: {}", err));
                }
            }

            if let Some(e) = &self.error {
                ui.add_space(8.0);
                ui.colored_label(egui::Color32::RED, e);
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if busy {
                    if ui.button("Cancel").clicked() {
                        if let Some(c) = &self.cancel {
                            c.cancel();
                        }
                    }
                } else if ui.button("Start transfer").clicked() {
                    self.error = None;
                    self.start(ctx);
                }
            });
        });

        if busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
    }
}
