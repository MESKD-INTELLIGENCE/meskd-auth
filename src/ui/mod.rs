mod clip;
mod dialogs;
#[cfg(test)]
mod tests;
pub mod theme;

use std::fs::File;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use egui::{Align, CursorIcon, Key, Layout, RichText, Sense, Stroke, TextEdit, Ui};
use meskd_auth::transfer::{self, Import};
use meskd_auth::{Entry, KdfParams, OtpKind, Vault, otp, vault};
use zeroize::Zeroizing;

use clip::Clip;
use dialogs::Dialog;

type Apply = Box<dyn FnOnce(&mut App) + Send>;

pub struct Config {
    pub path: PathBuf,
    pub params: KdfParams,
}

#[derive(Clone, Copy)]
enum Action {
    Add,
    ImportFiles,
    Paste,
    Export,
    Settings,
    Lock,
    Copy(usize),
    Next(usize),
    Edit(usize),
    Qr(usize),
    Delete(usize),
    Up(usize),
    Down(usize),
}

pub struct App {
    config: Config,
    lock_file: Option<File>,
    taken: bool,
    vault: Option<Vault>,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    error: Option<String>,
    job: Option<(String, Receiver<Apply>)>,
    dialog: Option<Dialog>,
    search: String,
    focus_search: bool,
    focus_password: bool,
    toast: Option<(String, Instant)>,
    last_input: Instant,
    clip: Clip,
}

impl App {
    pub fn new(config: Config) -> App {
        let (lock_file, taken, error) = match vault::acquire_lock(&config.path) {
            Ok(Some(file)) => (Some(file), false, None),
            Ok(None) => (None, true, None),
            Err(e) => (
                None,
                false,
                Some(format!("Could not prepare the data folder: {e}")),
            ),
        };
        App {
            config,
            lock_file,
            taken,
            vault: None,
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            error,
            job: None,
            dialog: None,
            search: String::new(),
            focus_search: false,
            focus_password: true,
            toast: None,
            last_input: Instant::now(),
            clip: Clip::default(),
        }
    }

    fn spawn(
        &mut self,
        label: &str,
        ctx: &egui::Context,
        work: impl FnOnce() -> Apply + Send + 'static,
    ) {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(work());
            ctx.request_repaint();
        });
        self.job = Some((label.to_owned(), rx));
    }

    fn poll_job(&mut self) {
        let apply: Option<Apply> = match &self.job {
            Some((_, rx)) => match rx.try_recv() {
                Ok(apply) => Some(apply),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Box::new(|app: &mut App| {
                    app.notify("Something went wrong, please try again");
                })),
            },
            None => None,
        };
        if let Some(apply) = apply {
            self.job = None;
            apply(self);
        }
    }

    fn notify(&mut self, message: impl Into<String>) {
        self.toast = Some((message.into(), Instant::now()));
    }

    fn settings(&self) -> meskd_auth::Settings {
        self.vault
            .as_ref()
            .map(|v| v.data.settings.clone())
            .unwrap_or_default()
    }

    fn save(&mut self) {
        if let Some(vault) = &self.vault
            && let Err(e) = vault.save()
        {
            self.notify(format!("Could not save: {e}"));
        }
    }

    fn create(&mut self, ctx: &egui::Context) {
        if self.password.chars().count() < vault::MIN_PASSWORD {
            self.error = Some(format!("Use at least {} characters", vault::MIN_PASSWORD));
            return;
        }
        if *self.password != *self.confirm {
            self.error = Some("The passwords do not match".to_owned());
            return;
        }
        self.error = None;
        let password = Zeroizing::new(std::mem::take(&mut *self.password));
        self.confirm = Zeroizing::new(String::new());
        let path = self.config.path.clone();
        let params = self.config.params;
        self.spawn("Creating your vault", ctx, move || {
            let result = Vault::create(&path, &password, params);
            Box::new(move |app: &mut App| match result {
                Ok(vault) => app.opened(vault),
                Err(e) => app.error = Some(e.to_string()),
            })
        });
    }

    fn unlock(&mut self, ctx: &egui::Context) {
        if self.password.is_empty() {
            return;
        }
        self.error = None;
        let password = Zeroizing::new(std::mem::take(&mut *self.password));
        let path = self.config.path.clone();
        self.spawn("Unlocking", ctx, move || {
            let result = Vault::open(&path, &password);
            Box::new(move |app: &mut App| match result {
                Ok(vault) => app.opened(vault),
                Err(e) => {
                    app.error = Some(e.to_string());
                    app.focus_password = true;
                }
            })
        });
    }

    fn opened(&mut self, vault: Vault) {
        self.vault = Some(vault);
        self.error = None;
        self.last_input = Instant::now();
    }

    fn lock(&mut self) {
        self.clip.clear_now();
        self.vault = None;
        self.dialog = None;
        self.search.clear();
        self.focus_password = true;
    }

    fn import_paths(&mut self, ctx: &egui::Context, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        self.spawn("Reading files", ctx, move || {
            let mut import = Import::default();
            let mut encrypted = None;
            let mut failures = Vec::new();
            for path in paths {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                match vault::read_limited(&path) {
                    Ok(bytes) if transfer::needs_password(&bytes) && encrypted.is_none() => {
                        encrypted = Some(bytes)
                    }
                    Ok(bytes) => match transfer::from_bytes(&bytes, None) {
                        Ok(found) => import.merge(found),
                        Err(e) => failures.push(format!("{name}: {e}")),
                    },
                    Err(e) => failures.push(format!("{name}: {e}")),
                }
            }
            import.problems.extend(failures);
            Box::new(move |app: &mut App| app.review(import, encrypted))
        });
    }

    fn import_clipboard(&mut self, ctx: &egui::Context) {
        if let Some((w, h, rgba)) = self.clip.image() {
            self.spawn("Reading the clipboard", ctx, move || {
                let result = meskd_auth::qr::decode_rgba(w, h, &rgba)
                    .and_then(|texts| transfer::from_qr_texts(&texts));
                Box::new(move |app: &mut App| match result {
                    Ok(import) => app.review(import, None),
                    Err(e) => app.notify(e.to_string()),
                })
            });
            return;
        }
        match self.clip.text() {
            Some(text) if !text.trim().is_empty() => self.import_text(ctx, Zeroizing::new(text)),
            _ => self.notify("The clipboard has no QR code, link or setup key"),
        }
    }

    fn import_text(&mut self, ctx: &egui::Context, text: Zeroizing<String>) {
        if let Some(key) = bare_key(&text) {
            self.dialog = Some(Dialog::add_with_key(key));
            return;
        }
        self.spawn("Reading the clipboard", ctx, move || {
            let result = transfer::from_bytes(text.as_bytes(), None);
            Box::new(move |app: &mut App| match result {
                Ok(import) => app.review(import, None),
                Err(_) => app.notify("The clipboard has no QR code, link or setup key"),
            })
        });
    }

    fn review(&mut self, import: Import, encrypted: Option<Vec<u8>>) {
        if let Some(bytes) = encrypted {
            self.dialog = Some(Dialog::backup_password(bytes, import));
        } else if import.entries.is_empty() && import.problems.is_empty() {
            self.notify("No accounts were found");
        } else {
            self.dialog = Some(Dialog::Preview(import));
        }
    }

    fn add_entries(&mut self, entries: Vec<Entry>) -> usize {
        let Some(vault) = &mut self.vault else {
            return 0;
        };
        let added = entries
            .into_iter()
            .filter(|e| vault.data.add(e.clone()))
            .count();
        if added > 0 {
            self.save();
        }
        added
    }

    fn copy_code(&mut self, index: usize) {
        let Some(vault) = &self.vault else { return };
        let Some(entry) = vault.data.entries.get(index) else {
            return;
        };
        let code = Zeroizing::new(entry.code(unix_now()));
        let seconds = vault.data.settings.clipboard_seconds;
        if self.clip.copy_secret(&code, seconds) {
            if seconds > 0 {
                self.notify(format!("Copied, the clipboard clears in {seconds} s"));
            } else {
                self.notify("Copied");
            }
        } else {
            self.notify("Could not reach the clipboard");
        }
    }

    fn run(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            Action::Add => self.dialog = Some(Dialog::add()),
            Action::ImportFiles => {
                if let Some(paths) = rfd::FileDialog::new()
                    .set_title("Import accounts")
                    .add_filter(
                        "Backups, exports and QR images",
                        &[
                            "meskd", "txt", "csv", "json", "png", "jpg", "jpeg", "webp", "bmp",
                            "gif",
                        ],
                    )
                    .add_filter("All files", &["*"])
                    .pick_files()
                {
                    self.import_paths(ctx, paths);
                }
            }
            Action::Paste => self.import_clipboard(ctx),
            Action::Export => self.dialog = Some(Dialog::export()),
            Action::Settings => self.dialog = Some(Dialog::settings(&self.settings())),
            Action::Lock => self.lock(),
            Action::Copy(i) => self.copy_code(i),
            Action::Next(i) => {
                if let Some(entry) = self.vault.as_mut().and_then(|v| v.data.entries.get_mut(i)) {
                    entry.advance_counter();
                    self.save();
                }
            }
            Action::Edit(i) => {
                if let Some(entry) = self.vault.as_ref().and_then(|v| v.data.entries.get(i)) {
                    self.dialog = Some(Dialog::edit(i, entry));
                }
            }
            Action::Qr(i) => {
                if let Some(entry) = self.vault.as_ref().and_then(|v| v.data.entries.get(i)) {
                    self.dialog = Dialog::qr(entry);
                }
            }
            Action::Delete(i) => self.dialog = Some(Dialog::Delete(i)),
            Action::Up(i) | Action::Down(i) => {
                if let Some(vault) = &mut self.vault {
                    let len = vault.data.entries.len();
                    let target = if matches!(action, Action::Up(_)) {
                        i.checked_sub(1)
                    } else {
                        Some(i + 1).filter(|t| *t < len)
                    };
                    if let Some(t) = target {
                        vault.data.entries.swap(i, t);
                        self.save();
                    }
                }
            }
        }
    }

    fn track_input(&mut self, ctx: &egui::Context) {
        let active =
            ctx.input(|i| !i.events.is_empty() || i.pointer.is_moving() || i.pointer.any_down());
        if active {
            self.last_input = Instant::now();
        }
        let minutes = self.settings().lock_minutes;
        if self.vault.is_some()
            && minutes > 0
            && self.last_input.elapsed() >= Duration::from_secs(u64::from(minutes) * 60)
        {
            self.lock();
            self.notify("Locked after inactivity");
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context) -> Option<Action> {
        if self.vault.is_none() || self.dialog.is_some() || self.job.is_some() {
            return None;
        }
        let typing = ctx.text_edit_focused();
        ctx.input_mut(|i| {
            if i.consume_key(egui::Modifiers::COMMAND, Key::L) {
                return Some(Action::Lock);
            }
            if i.consume_key(egui::Modifiers::COMMAND, Key::F) {
                self.focus_search = true;
            }
            if i.consume_key(egui::Modifiers::COMMAND, Key::N) {
                return Some(Action::Add);
            }
            let pasted = i.events.iter().any(|e| {
                matches!(e, egui::Event::Paste(_))
                    || matches!(e, egui::Event::Key { key: Key::V, pressed: true, modifiers, .. } if modifiers.command)
            });
            (pasted && !typing).then_some(Action::Paste)
        })
    }

    fn dropped(&mut self, ctx: &egui::Context) {
        let paths: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if paths.is_empty() || self.job.is_some() {
            return;
        }
        if self.vault.is_some() {
            self.dialog = None;
            self.import_paths(ctx, paths);
        } else {
            self.notify("Unlock first, then drop the file again");
        }
    }

    fn gate(&mut self, ui: &mut Ui, setup: bool) {
        let ctx = ui.ctx().clone();
        column(ui, 340.0, |ui| {
            theme::logo(ui, 56.0);
            ui.add_space(6.0);
            ui.label(RichText::new("Meskd Authenticator").size(22.0).strong());
            ui.add_space(2.0);
            let intro = if setup {
                "Pick a password to encrypt your accounts on this computer. There is no way to recover it, so keep it somewhere safe."
            } else {
                "Enter your password to unlock."
            };
            ui.label(RichText::new(intro).color(theme::MUTED));
            ui.add_space(10.0);

            let first = ui.add(
                TextEdit::singleline(&mut *self.password)
                    .password(true)
                    .hint_text("Password")
                    .desired_width(f32::INFINITY),
            );
            theme::name(&first, "Password");
            if self.focus_password {
                first.request_focus();
                self.focus_password = false;
            }
            let enter = ui.input(|i| i.key_pressed(Key::Enter));
            let mut submit = first.lost_focus() && enter;
            if setup {
                let second = ui.add(
                    TextEdit::singleline(&mut *self.confirm)
                        .password(true)
                        .hint_text("Repeat password")
                        .desired_width(f32::INFINITY),
                );
                theme::name(&second, "Repeat password");
                if submit {
                    second.request_focus();
                    submit = false;
                }
                submit |= second.lost_focus() && enter;
            }
            if let Some(error) = &self.error {
                ui.label(RichText::new(error).color(theme::DANGER));
            }
            ui.add_space(4.0);
            let label = if setup { "Create vault" } else { "Unlock" };
            let button = ui.add_sized([ui.available_width(), 34.0], theme::primary(label));
            if button.clicked() || submit {
                if setup {
                    self.create(&ctx);
                } else {
                    self.unlock(&ctx);
                }
            }
            if setup {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!("Stored at {}", self.config.path.display()))
                        .small()
                        .color(theme::MUTED),
                );
            }
        });
    }

    fn busy(&mut self, ui: &mut Ui) {
        let label = self
            .job
            .as_ref()
            .map(|(l, _)| l.clone())
            .unwrap_or_default();
        column(ui, 340.0, |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new(label).color(theme::MUTED));
            });
        });
    }

    fn main_view(&mut self, ui: &mut Ui) -> Option<Action> {
        let mut action = None;
        ui.horizontal(|ui| {
            let search_width = (ui.available_width() - 150.0).max(80.0);
            let search = ui.add(
                TextEdit::singleline(&mut self.search)
                    .hint_text("Search")
                    .desired_width(search_width),
            );
            theme::name(&search, "Search");
            if self.focus_search {
                search.request_focus();
                self.focus_search = false;
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button("Menu", |ui| {
                    ui.set_min_width(190.0);
                    if ui.button("Import from file").clicked() {
                        action = Some(Action::ImportFiles);
                    }
                    if ui.button("Paste from clipboard").clicked() {
                        action = Some(Action::Paste);
                    }
                    if ui.button("Export").clicked() {
                        action = Some(Action::Export);
                    }
                    ui.separator();
                    if ui.button("Settings").clicked() {
                        action = Some(Action::Settings);
                    }
                    if ui
                        .add(egui::Button::new("Lock").shortcut_text("Ctrl+L"))
                        .clicked()
                    {
                        action = Some(Action::Lock);
                    }
                    if action.is_some() {
                        ui.close();
                    }
                });
                if ui.add(theme::primary("Add")).clicked() {
                    action = Some(Action::Add);
                }
            });
        });
        ui.add_space(6.0);

        let Some(vault) = &self.vault else {
            return action;
        };
        let entries = &vault.data.entries;
        if entries.is_empty() {
            column(ui, 340.0, |ui| {
                ui.label(RichText::new("No accounts yet").size(18.0).strong());
                ui.label(
                    RichText::new(
                        "Scan a QR code image, paste a setup key, or bring your accounts over from Google Authenticator or a backup.",
                    )
                    .color(theme::MUTED),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::primary("Add account")).clicked() {
                        action = Some(Action::Add);
                    }
                    if ui.button("Import").clicked() {
                        action = Some(Action::ImportFiles);
                    }
                });
                ui.add_space(6.0);
                ui.label(
                    RichText::new("You can also drop files on this window, or press Ctrl+V to paste a QR screenshot, a link or a setup key.")
                        .small()
                        .color(theme::MUTED),
                );
            });
            return action;
        }

        let hide = vault.data.settings.hide_codes;
        let query = self.search.trim().to_lowercase();
        let now = unix_now_f64();
        let total = entries.len();
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                let mut shown = 0;
                for (index, entry) in entries.iter().enumerate() {
                    if !query.is_empty()
                        && !entry.issuer.to_lowercase().contains(&query)
                        && !entry.account.to_lowercase().contains(&query)
                    {
                        continue;
                    }
                    shown += 1;
                    if let Some(a) = row(ui, index, total, entry, now, hide) {
                        action = Some(a);
                    }
                }
                if shown == 0 {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("No matches").color(theme::MUTED))
                    });
                }
            });
        action
    }

    fn show_toast(&mut self, ctx: &egui::Context) {
        let Some((message, at)) = &self.toast else {
            return;
        };
        if at.elapsed() > Duration::from_millis(3200) {
            self.toast = None;
            return;
        }
        egui::Area::new(egui::Id::unique("toast"))
            .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -18.0])
            .order(egui::Order::Tooltip)
            .interactable(false)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(theme::CARD_HOVER)
                    .stroke(Stroke::new(1.0, theme::LINE))
                    .corner_radius(8)
                    .inner_margin(egui::Margin::symmetric(14, 8))
                    .show(ui, |ui| ui.label(message.as_str()));
            });
    }

    fn schedule(&self, ctx: &egui::Context) {
        let mut wait = Duration::from_secs(3600);
        if self.vault.is_some() {
            wait = wait.min(Duration::from_millis(200));
        }
        if self.toast.is_some() || self.job.is_some() {
            wait = wait.min(Duration::from_millis(100));
        }
        if let Some(at) = self.clip.next_deadline() {
            wait = wait.min(at.saturating_duration_since(Instant::now()));
        }
        ctx.request_repaint_after(wait);
    }

    fn frame(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        self.poll_job();
        self.clip.tick();
        self.track_input(&ctx);
        self.dropped(&ctx);
        let mut action = self.shortcuts(&ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::BG).inner_margin(16))
            .show(ui, |ui| {
                if self.taken {
                    column(ui, 340.0, |ui| {
                        ui.label(RichText::new("Already open").size(18.0).strong());
                        ui.label(
                            RichText::new(
                                "Meskd Authenticator is already running in another window.",
                            )
                            .color(theme::MUTED),
                        );
                    });
                } else if self.job.is_some() && self.vault.is_none() {
                    self.busy(ui);
                } else if self.vault.is_some() {
                    if let Some(a) = self.main_view(ui) {
                        action = Some(a);
                    }
                } else if self.lock_file.is_none() {
                    column(ui, 340.0, |ui| {
                        ui.label(
                            RichText::new(self.error.clone().unwrap_or_default())
                                .color(theme::DANGER),
                        );
                    });
                } else {
                    let setup = !self.config.path.exists();
                    self.gate(ui, setup);
                }
            });

        if let Some(action) = action {
            self.run(action, &ctx);
        }
        self.show_dialog(&ctx);
        if self.job.is_some() && self.vault.is_some() {
            busy_overlay(
                &ctx,
                self.job
                    .as_ref()
                    .map(|(l, _)| l.as_str())
                    .unwrap_or_default(),
            );
        }
        self.show_toast(&ctx);
        self.schedule(&ctx);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.clip.clear_now();
    }
}

fn row(
    ui: &mut Ui,
    index: usize,
    total: usize,
    entry: &Entry,
    now: f64,
    hide: bool,
) -> Option<Action> {
    let mut action = None;
    let id = egui::Id::unique(("row", &entry.id));
    let hovered = ui.ctx().read_response(id).is_some_and(|r| r.hovered());
    let response = ui
        .scope_builder(
            egui::UiBuilder::new().scope_id(id).sense(Sense::click()),
            |ui| {
                theme::card()
                    .fill(if hovered {
                        theme::CARD_HOVER
                    } else {
                        theme::CARD
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(entry.title()).size(15.5).strong(),
                                    )
                                    .truncate()
                                    .selectable(false),
                                );
                                let sub = entry.subtitle();
                                if !sub.is_empty() {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(sub).size(12.5).color(theme::MUTED),
                                        )
                                        .truncate()
                                        .selectable(false),
                                    );
                                }
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.menu_button(RichText::new("...").strong(), |ui| {
                                    ui.set_min_width(160.0);
                                    if let Some(a) = entry_menu(ui, index, total, entry) {
                                        action = Some(a);
                                    }
                                });
                                if let OtpKind::Hotp { .. } = entry.kind
                                    && ui
                                        .small_button("Next")
                                        .on_hover_text("Generate the next code")
                                        .clicked()
                                {
                                    action = Some(Action::Next(index));
                                }
                                let code = if hide && !hovered {
                                    "\u{2022}".repeat(entry.digits as usize)
                                } else {
                                    entry.code(now as u64)
                                };
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(group(&code))
                                            .monospace()
                                            .size(24.0)
                                            .color(theme::TEXT),
                                    )
                                    .selectable(false),
                                );
                            });
                        });
                        if let OtpKind::Totp { period } = entry.kind {
                            progress(ui, now, period);
                        }
                    });
            },
        )
        .response;
    let response = response.on_hover_cursor(CursorIcon::PointingHand);
    if response.clicked() && action.is_none() {
        action = Some(Action::Copy(index));
    }
    response.context_menu(|ui| {
        ui.set_min_width(160.0);
        if let Some(a) = entry_menu(ui, index, total, entry) {
            action = Some(a);
        }
    });
    action
}

fn entry_menu(ui: &mut Ui, index: usize, total: usize, entry: &Entry) -> Option<Action> {
    let mut action = None;
    if ui.button("Copy code").clicked() {
        action = Some(Action::Copy(index));
    }
    if !entry.kind.is_totp() && ui.button("Next code").clicked() {
        action = Some(Action::Next(index));
    }
    if ui.button("Show QR code").clicked() {
        action = Some(Action::Qr(index));
    }
    if ui.button("Edit name").clicked() {
        action = Some(Action::Edit(index));
    }
    if index > 0 && ui.button("Move up").clicked() {
        action = Some(Action::Up(index));
    }
    if index + 1 < total && ui.button("Move down").clicked() {
        action = Some(Action::Down(index));
    }
    ui.separator();
    if ui
        .button(RichText::new("Delete").color(theme::DANGER))
        .clicked()
    {
        action = Some(Action::Delete(index));
    }
    if action.is_some() {
        ui.close();
    }
    action
}

fn progress(ui: &mut Ui, now: f64, period: u32) {
    let period_f = f64::from(period.max(1));
    let left = period_f - now.rem_euclid(period_f);
    let fraction = (left / period_f) as f32;
    let color = if otp::seconds_left(now as u64, period) <= 5 {
        theme::WARN
    } else {
        theme::ACCENT
    };
    ui.add_space(2.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 3.0), Sense::hover());
    ui.painter().rect_filled(rect, 2.0, theme::LINE);
    let mut filled = rect;
    filled.set_width(rect.width() * fraction);
    ui.painter().rect_filled(filled, 2.0, color);
}

fn busy_overlay(ctx: &egui::Context, label: &str) {
    egui::Modal::new(egui::Id::unique("busy"))
        .frame(theme::dialog())
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(label);
            });
        });
}

pub fn column(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui)) {
    let width = width.min(ui.available_width());
    let pad = ((ui.available_width() - width) / 2.0).max(0.0);
    let top = (ui.available_height() * 0.18).clamp(12.0, 140.0);
    ui.add_space(top);
    ui.horizontal(|ui| {
        ui.add_space(pad);
        ui.vertical(|ui| {
            ui.set_width(width);
            add(ui);
        });
    });
}

fn bare_key(text: &str) -> Option<Zeroizing<String>> {
    let text = text.trim();
    if text.to_ascii_lowercase().contains("otpauth") {
        return None;
    }
    let significant = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .count();
    if !(16..=256).contains(&significant) {
        return None;
    }
    meskd_auth::entry::parse_secret(text)
        .ok()
        .map(|_| Zeroizing::new(text.to_owned()))
}

pub fn group(code: &str) -> String {
    let split = match code.chars().count() {
        6 => 3,
        7 => 3,
        8 => 4,
        _ => return code.to_owned(),
    };
    let chars: Vec<char> = code.chars().collect();
    let (a, b) = chars.split_at(split);
    format!(
        "{} {}",
        a.iter().collect::<String>(),
        b.iter().collect::<String>()
    )
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn today() -> String {
    let days = (unix_now() / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
