pub mod sender_gui;
pub mod receiver_gui;

pub use sender_gui::SenderApp;
pub use receiver_gui::ReceiverApp;

#[cfg(feature = "gui")]
use anyhow::Result;

#[cfg(feature = "gui")]
use std::net::SocketAddr;

#[cfg(feature = "gui")]
use std::path::PathBuf;

#[cfg(feature = "gui")]
use eframe::egui;

#[cfg(feature = "gui")]
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
    )
        .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}

#[cfg(feature = "gui")]
pub fn run_receiver_gui(_output: PathBuf, _bind: SocketAddr) -> Result<()> {
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
    )
        .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}