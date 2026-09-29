//! Asking for the passphrase of a sealed identity file in a window, and
//! opening the file on a thread of its own (Argon2 takes about a second,
//! which would freeze the window).

use crate::crypto::identity_file::IdentityFile;
use crate::crypto::{Identity, SharpId};
use eframe::egui;
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroize;

type Opening = Arc<Mutex<Option<Result<Identity, String>>>>;

pub struct Unlock {
    path: PathBuf,
    id: SharpId,
    passphrase: String,
    opening: Option<Opening>,
    error: Option<String>,
}

impl Unlock {
    pub fn new(path: PathBuf, id: SharpId) -> Self {
        Self {
            path,
            id,
            passphrase: String::new(),
            opening: None,
            error: None,
        }
    }

    /// Draws the question; gives the identity once the passphrase has
    /// opened it.
    pub fn show(&mut self, ui: &mut egui::Ui) -> Option<Identity> {
        if let Some(opening) = &self.opening {
            let done = opening.lock().take();
            match done {
                Some(Ok(identity)) => {
                    self.opening = None;
                    return Some(identity);
                }
                Some(Err(e)) => {
                    self.opening = None;
                    self.error = Some(e);
                }
                None => {
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(100));
                }
            }
        }
        ui.label(format!(
            "Identity {} is sealed with a passphrase.",
            self.id.short()
        ));
        ui.label(format!("File: {}", self.path.display()));
        let mut go = false;
        ui.horizontal(|ui| {
            ui.label("Passphrase:");
            let field = ui.add_enabled(
                self.opening.is_none(),
                egui::TextEdit::singleline(&mut self.passphrase).password(true),
            );
            if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                go = true;
            }
            if ui
                .add_enabled(self.opening.is_none(), egui::Button::new("Unlock"))
                .clicked()
            {
                go = true;
            }
        });
        if self.opening.is_some() {
            ui.label("Opening…");
        } else if let Some(e) = &self.error {
            ui.colored_label(egui::Color32::RED, e);
        }
        if go && self.opening.is_none() {
            let opening: Opening = Arc::new(Mutex::new(None));
            let (path, into) = (self.path.clone(), opening.clone());
            let mut passphrase = std::mem::take(&mut self.passphrase);
            std::thread::spawn(move || {
                let result = IdentityFile::read(&path)
                    .and_then(|f| f.open(Some(&passphrase)))
                    .map_err(|e| e.to_string());
                passphrase.zeroize();
                *into.lock() = Some(result);
            });
            self.error = None;
            self.opening = Some(opening);
        }
        None
    }
}

impl Drop for Unlock {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}
