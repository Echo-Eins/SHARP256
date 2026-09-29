//! Desktop front ends (egui/eframe). Both windows drive the real transport
//! engines and render the events they emit.

pub mod receiver_gui;
pub mod sender_gui;
mod unlock;

use anyhow::Result;
use std::path::PathBuf;

pub use receiver_gui::ReceiverApp;
pub use sender_gui::SenderApp;

/// Opens the sender window; `file` may be a file or a directory.
pub fn run_sender_gui(file: Option<PathBuf>, receiver: Option<String>) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 480.0])
            .with_title("SHARP-256 Sender"),
        ..Default::default()
    };
    eframe::run_native(
        "SHARP-256 Sender",
        options,
        Box::new(move |_cc| Box::new(SenderApp::new(file, receiver))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}

/// Opens the receiver window. Without an identity in `cfg`, the one in
/// `identity_path` is sealed with a passphrase: the window asks for it.
pub fn run_receiver_gui(cfg: crate::config::ReceiverConfig, identity_path: PathBuf) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 560.0])
            .with_title("SHARP-256 Receiver"),
        ..Default::default()
    };
    eframe::run_native(
        "SHARP-256 Receiver",
        options,
        Box::new(move |_cc| Box::new(ReceiverApp::new(cfg, identity_path))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}
