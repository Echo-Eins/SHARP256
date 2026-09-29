use crate::config::{AcceptPolicy, IncomingRequest, ReceiverConfig};
use crate::progress::{format_bytes, format_rate, DirectoryInfo, TransferEvent, TransferStats};
use crate::transport::Receiver;
use eframe::egui;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
struct Active {
    transfer_id: String,
    peer: String,
    peer_id: String,
    cipher: String,
    file_name: String,
    directory: Option<DirectoryInfo>,
    stats: Option<TransferStats>,
    stalled: bool,
}

#[derive(Debug, Clone)]
struct Finished {
    file_name: String,
    path: String,
    size: u64,
    ok: bool,
    detail: String,
}

struct PendingRequest {
    request: IncomingRequest,
    reply: Option<oneshot::Sender<bool>>,
}

#[derive(Default)]
struct Shared {
    active: Vec<Active>,
    history: VecDeque<Finished>,
    pending: Vec<PendingRequest>,
    listen: String,
    receiver_id: String,
    /// How a sender is told to reach us.
    contact: String,
    reachability: Option<String>,
    /// Relays that have taken our registration, as senders should name them.
    relays: Vec<String>,
    error: Option<String>,
}

pub struct ReceiverApp {
    shared: Arc<Mutex<Shared>>,
    output_dir: String,
    cancel: CancellationToken,
    /// The configuration, while the identity file waits for its passphrase.
    locked: Option<(super::unlock::Unlock, ReceiverConfig)>,
}

impl ReceiverApp {
    /// A window receiving with `cfg`; if `cfg` has no identity, the one in
    /// `identity_path` is sealed with a passphrase, which is asked for first.
    pub fn new(mut cfg: ReceiverConfig, identity_path: std::path::PathBuf) -> Self {
        let id = match &cfg.identity {
            Some(identity) => Some(identity.id()),
            None => crate::crypto::identity_file::id_of(&identity_path).ok(),
        };
        let shared = Arc::new(Mutex::new(Shared {
            listen: cfg.bind.to_string(),
            receiver_id: id.map(|i| i.to_string()).unwrap_or_default(),
            contact: id.map(|i| cfg.contact_hint(&i)).unwrap_or_default(),
            ..Default::default()
        }));
        let output_dir = cfg.output_dir.display().to_string();
        let cancel = CancellationToken::new();

        let s = shared.clone();
        cfg.accept = AcceptPolicy::Ask(Arc::new(move |req, reply| {
            s.lock().pending.push(PendingRequest {
                request: req,
                reply: Some(reply),
            });
        }));
        let s = shared.clone();
        cfg.events = Some(Arc::new(move |ev: TransferEvent| {
            let mut sh = s.lock();
            match ev {
                TransferEvent::Started {
                    transfer_id,
                    peer,
                    peer_id,
                    cipher,
                    file_name,
                    directory,
                    ..
                } => {
                    sh.active.retain(|a| a.transfer_id != transfer_id);
                    sh.active.push(Active {
                        transfer_id,
                        peer,
                        peer_id,
                        cipher,
                        file_name,
                        directory,
                        stats: None,
                        stalled: false,
                    });
                }
                TransferEvent::Progress(st) => {
                    if let Some(a) = sh
                        .active
                        .iter_mut()
                        .find(|a| a.transfer_id == st.transfer_id)
                    {
                        a.stalled = st.stalled;
                        a.stats = Some(st);
                    }
                }
                TransferEvent::Stalled { transfer_id, .. } => {
                    if let Some(a) = sh.active.iter_mut().find(|a| a.transfer_id == transfer_id) {
                        a.stalled = true;
                    }
                }
                TransferEvent::Recovered { transfer_id } => {
                    if let Some(a) = sh.active.iter_mut().find(|a| a.transfer_id == transfer_id) {
                        a.stalled = false;
                    }
                }
                TransferEvent::Completed {
                    transfer_id,
                    file_name,
                    path,
                    file_hash_hex,
                    peer_confirmed,
                    stats,
                } => {
                    sh.active.retain(|a| a.transfer_id != transfer_id);
                    sh.history.push_front(Finished {
                        file_name,
                        path: path.unwrap_or_default(),
                        size: stats.total_bytes,
                        ok: true,
                        detail: format!(
                            "{:.1} s, {}, BLAKE3 {}{}",
                            stats.elapsed.as_secs_f64(),
                            format_rate(stats.avg_rate_bps),
                            &file_hash_hex[..16],
                            if peer_confirmed { "" } else { " (unconfirmed)" }
                        ),
                    });
                    sh.history.truncate(50);
                }
                TransferEvent::Failed {
                    transfer_id, error, ..
                } => {
                    if let Some(pos) = sh.active.iter().position(|a| a.transfer_id == transfer_id) {
                        let a = sh.active.remove(pos);
                        sh.history.push_front(Finished {
                            file_name: a.file_name,
                            path: String::new(),
                            size: a.stats.map(|s| s.total_bytes).unwrap_or(0),
                            ok: false,
                            detail: error,
                        });
                    }
                }
                TransferEvent::Reachability { summary, .. } => sh.reachability = Some(summary),
                // Its own line, not the network summary: the two arrive in
                // either order, and one overwriting the other lost whichever
                // came first.
                TransferEvent::RelayRegistered { relay, .. } => {
                    if !sh.relays.contains(&relay) {
                        sh.relays.push(relay);
                    }
                }
                TransferEvent::IncomingRequest { .. } | TransferEvent::ContactCard { .. } => {}
            }
        }));

        let mut app = Self {
            shared,
            output_dir,
            cancel,
            locked: None,
        };
        match (cfg.identity.is_some(), id) {
            (false, Some(id)) => {
                app.locked = Some((super::unlock::Unlock::new(identity_path, id), cfg));
            }
            _ => app.start(cfg),
        }
        app
    }

    /// Starts the receiver on a thread of its own.
    fn start(&mut self, cfg: ReceiverConfig) {
        let s = self.shared.clone();
        let token = self.cancel.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    s.lock().error = Some(format!("runtime: {}", e));
                    return;
                }
            };
            rt.block_on(async move {
                match Receiver::new(cfg).await {
                    Ok(receiver) => {
                        if let Ok(addr) = receiver.local_addr() {
                            s.lock().listen = addr.to_string();
                        }
                        s.lock().receiver_id = receiver.id().to_string();
                        let rt_token = receiver.cancel_token();
                        tokio::spawn(async move {
                            token.cancelled().await;
                            rt_token.cancel();
                        });
                        if let Err(e) = receiver.run().await {
                            s.lock().error = Some(e.to_string());
                        }
                    }
                    Err(e) => s.lock().error = Some(format!("cannot start receiver: {}", e)),
                }
            });
        });
    }
}

impl eframe::App for ReceiverApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some((unlock, _)) = &mut self.locked {
            let mut opened = None;
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("SHARP-256 Receiver");
                ui.separator();
                opened = unlock.show(ui);
            });
            if let Some(identity) = opened {
                let (_, mut cfg) = self.locked.take().expect("locked");
                cfg.identity = Some(identity);
                self.start(cfg);
            }
            return;
        }
        // Incoming requests: one modal at a time.
        let mut decision: Option<(usize, bool)> = None;
        {
            let sh = self.shared.lock();
            if let Some(p) = sh.pending.first() {
                let r = &p.request;
                egui::Window::new("Incoming transfer")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(format!("From: {}", r.peer));
                        ui.label(format!("Sender ID: {}", r.sender_id));
                        match &r.directory {
                            Some(d) => {
                                ui.label(format!("Folder: {}", r.file_name));
                                ui.label(format!(
                                    "Contents: {}, {}",
                                    d.describe(),
                                    format_bytes(r.file_size)
                                ));
                            }
                            None => {
                                ui.label(format!("File: {}", r.file_name));
                                ui.label(format!("Size: {}", format_bytes(r.file_size)));
                            }
                        }
                        if r.resumed_bytes > 0 {
                            ui.label(format!(
                                "Resume: {} already stored",
                                format_bytes(r.resumed_bytes)
                            ));
                        }
                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui.button("Accept").clicked() {
                                decision = Some((0, true));
                            }
                            if ui.button("Reject").clicked() {
                                decision = Some((0, false));
                            }
                        });
                    });
            }
        }
        if let Some((idx, ok)) = decision {
            let mut sh = self.shared.lock();
            if idx < sh.pending.len() {
                let mut p = sh.pending.remove(idx);
                if let Some(reply) = p.reply.take() {
                    let _ = reply.send(ok);
                }
            }
        }

        let sh = self.shared.lock().clone_view();
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SHARP-256 File Receiver");
            ui.separator();
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(format!("Receiver ID: {}", sh.receiver_id));
                    if ui.small_button("Copy").clicked() {
                        ui.output_mut(|o| o.copied_text = sh.receiver_id.clone());
                    }
                });
                ui.label(format!("Listening on {}", sh.listen));
                ui.label(format!("Senders use: {}", sh.contact));
                ui.label(format!("Output directory: {}", self.output_dir));
                if let Some(r) = &sh.reachability {
                    ui.label(format!("Network: {}", r));
                }
                for relay in &sh.relays {
                    ui.label(format!(
                        "Registered with relay {}: senders can add --relay {}",
                        relay, relay
                    ));
                }
            });
            if let Some(e) = &sh.error {
                ui.colored_label(egui::Color32::RED, e);
            }
            ui.add_space(10.0);
            ui.heading("Active transfers");
            if sh.active.is_empty() {
                ui.label("Waiting for incoming transfers...");
            }
            for a in &sh.active {
                ui.group(|ui| {
                    match &a.directory {
                        Some(d) => ui.label(format!(
                            "folder {} ({}) from {}",
                            a.file_name,
                            d.describe(),
                            a.peer
                        )),
                        None => ui.label(format!("{} from {}", a.file_name, a.peer)),
                    };
                    ui.label(format!("sender {}, {}", a.peer_id, a.cipher));
                    if let Some(s) = &a.stats {
                        ui.add(
                            egui::ProgressBar::new(s.fraction())
                                .text(format!("{:.1}%", s.fraction() * 100.0))
                                .animate(!a.stalled),
                        );
                        ui.label(format!(
                            "{} of {}  |  {}{}",
                            format_bytes(s.bytes_done),
                            format_bytes(s.total_bytes),
                            format_rate(s.rate_bps),
                            if a.stalled {
                                "  [stalled: waiting for sender]"
                            } else {
                                ""
                            }
                        ));
                    } else {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("starting...");
                        });
                    }
                });
            }
            ui.add_space(10.0);
            ui.heading("History");
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(ui, |ui| {
                    if sh.history.is_empty() {
                        ui.label("No transfers yet");
                    }
                    for f in &sh.history {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                if f.ok {
                                    ui.colored_label(egui::Color32::GREEN, "OK");
                                } else {
                                    ui.colored_label(egui::Color32::RED, "FAILED");
                                }
                                ui.label(&f.file_name);
                                ui.label(format_bytes(f.size));
                            });
                            if !f.path.is_empty() {
                                ui.label(&f.path);
                            }
                            ui.label(&f.detail);
                        });
                    }
                });
        });
        ctx.request_repaint_after(std::time::Duration::from_millis(300));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.cancel.cancel();
    }
}

#[derive(Clone)]
struct View {
    active: Vec<Active>,
    history: VecDeque<Finished>,
    listen: String,
    receiver_id: String,
    contact: String,
    reachability: Option<String>,
    relays: Vec<String>,
    error: Option<String>,
}

impl Shared {
    fn clone_view(&self) -> View {
        View {
            active: self.active.clone(),
            history: self.history.clone(),
            listen: self.listen.clone(),
            receiver_id: self.receiver_id.clone(),
            contact: self.contact.clone(),
            reachability: self.reachability.clone(),
            relays: self.relays.clone(),
            error: self.error.clone(),
        }
    }
}
