use crate::config::SenderConfig;
use crate::crypto::{psk_from_passphrase, Identity};
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
    secret: String,
    identity: Result<Identity, String>,
    state: Arc<Mutex<State>>,
    cancel: Option<CancellationToken>,
    error: Option<String>,
    pick_file: bool,
    pick_folder: bool,
}

impl SenderApp {
    pub fn new(file: Option<PathBuf>, receiver: Option<String>) -> Self {
        let identity = Identity::default_path()
            .ok_or_else(|| "no per-user data directory".to_string())
            .and_then(|p| {
                Identity::load_or_create(&p).map_err(|e| format!("{}: {}", p.display(), e))
            });
        Self {
            file_path: file,
            receiver_addr: receiver.unwrap_or_default(),
            bind_addr: "0.0.0.0:0".to_string(),
            max_rate: String::new(),
            secret: String::new(),
            identity,
            state: Arc::new(Mutex::new(State::Idle)),
            cancel: None,
            error: None,
            pick_file: false,
            pick_folder: false,
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Some(file) = self.file_path.clone() else {
            self.error = Some("Select a file or folder first".into());
            return;
        };
        let identity = match &self.identity {
            Ok(id) => id.clone(),
            Err(e) => {
                self.error = Some(format!("No identity: {}", e));
                return;
            }
        };
        let (receiver_id, hosts) = match crate::address::parse_peer(&self.receiver_addr) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(e);
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
        let max_rate = if self.max_rate.trim().is_empty() {
            None
        } else {
            match crate::progress::parse_rate(&self.max_rate) {
                Ok(bps) => Some(bps / 8),
                Err(e) => {
                    self.error = Some(e);
                    return;
                }
            }
        };
        let secret = (!self.secret.is_empty()).then(|| self.secret.clone());
        let state = self.state.clone();
        let repaint = ctx.clone();
        let events: crate::progress::EventCallback = Arc::new(move |ev: TransferEvent| {
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
        });

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
                let addrs = match crate::address::resolve_candidates(&hosts).await {
                    Ok(a) => a,
                    Err(e) => {
                        *state.lock() = State::Failed(e);
                        repaint.request_repaint();
                        return;
                    }
                };
                let mut cfg = SenderConfig::new(addrs[0], receiver_id, file);
                cfg.alternate_peers = addrs[1..].to_vec();
                cfg.bind = bind;
                cfg.identity = Some(identity);
                cfg.transport.max_rate_bytes = max_rate;
                cfg.psk = secret.map(|s| psk_from_passphrase(&s, &receiver_id));
                cfg.events = Some(events);
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
        if self.pick_folder {
            self.pick_folder = false;
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select folder to send")
                .pick_folder()
            {
                self.file_path = Some(path);
            }
        }

        let state = self.state.lock().clone();
        let busy = matches!(state, State::Connecting | State::Transferring(_));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SHARP-256 File Sender");
            match &self.identity {
                Ok(id) => {
                    ui.horizontal(|ui| {
                        ui.label(format!("This sender: {}", id.id()));
                        if ui.small_button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = id.id().to_string());
                        }
                    });
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::RED, format!("No identity: {}", e));
                }
            }
            ui.separator();
            ui.add_enabled_ui(!busy, |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Send:");
                        match &self.file_path {
                            Some(p) => {
                                let name = p
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| p.display().to_string());
                                match std::fs::metadata(p) {
                                    Ok(m) if m.is_dir() => {
                                        ui.label(format!("folder {}", name));
                                    }
                                    Ok(m) => {
                                        ui.label(format!("{} ({})", name, format_bytes(m.len())));
                                    }
                                    Err(_) => {
                                        ui.label(name);
                                    }
                                }
                            }
                            None => {
                                ui.label("nothing selected");
                            }
                        }
                        if ui.button("File...").clicked() {
                            self.pick_file = true;
                        }
                        if ui.button("Folder...").clicked() {
                            self.pick_folder = true;
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Receiver (ID@host:port):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.receiver_addr)
                                .hint_text("sh-…@192.168.1.100:5555")
                                .desired_width(420.0),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label("Shared secret (optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.secret).password(true));
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
