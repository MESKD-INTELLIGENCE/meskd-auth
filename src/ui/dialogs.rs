use egui::{Color32, Id, Key, Layout, Rect, RichText, Sense, TextEdit, Ui, vec2};
use meskd_auth::entry::parse_secret;
use meskd_auth::qr::{self, Matrix};
use meskd_auth::transfer::{self, Import};
use meskd_auth::{Algorithm, Entry, OtpKind, Settings, migration, vault};
use zeroize::Zeroizing;

use super::{App, theme, today};

const WIDTH: f32 = 380.0;

pub enum Dialog {
    Add(Box<AddForm>),
    Edit {
        index: usize,
        issuer: String,
        account: String,
    },
    Delete(usize),
    Qr {
        title: String,
        matrix: Matrix,
    },
    Preview(Import),
    BackupPassword {
        bytes: Vec<u8>,
        pending: Import,
        password: Zeroizing<String>,
        error: Option<String>,
    },
    Export(Box<ExportForm>),
    Google {
        pages: Vec<Matrix>,
        index: usize,
        skipped: usize,
    },
    Settings(Box<SettingsForm>),
}

pub struct AddForm {
    pub(super) issuer: String,
    pub(super) account: String,
    pub(super) secret: Zeroizing<String>,
    pub(super) totp: bool,
    pub(super) algorithm: Algorithm,
    pub(super) digits: u32,
    pub(super) period: u32,
    pub(super) counter: u64,
    pub(super) error: Option<String>,
    pub(super) focus: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum ExportKind {
    Backup,
    Text,
    Google,
}

pub struct ExportForm {
    kind: ExportKind,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    understood: bool,
    error: Option<String>,
}

pub struct SettingsForm {
    lock_minutes: u32,
    clipboard_seconds: u32,
    hide_codes: bool,
    current: Zeroizing<String>,
    new: Zeroizing<String>,
    confirm: Zeroizing<String>,
    error: Option<String>,
}

enum Next {
    Keep,
    Close,
    Replace(Dialog),
}

impl Dialog {
    pub fn add() -> Dialog {
        Dialog::Add(Box::new(AddForm {
            issuer: String::new(),
            account: String::new(),
            secret: Zeroizing::new(String::new()),
            totp: true,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            error: None,
            focus: true,
        }))
    }

    pub fn add_with_key(key: Zeroizing<String>) -> Dialog {
        let mut dialog = Dialog::add();
        if let Dialog::Add(form) = &mut dialog {
            form.secret = key;
        }
        dialog
    }

    pub fn edit(index: usize, entry: &Entry) -> Dialog {
        Dialog::Edit {
            index,
            issuer: entry.issuer.clone(),
            account: entry.account.clone(),
        }
    }

    pub fn qr(entry: &Entry) -> Option<Dialog> {
        let uri = Zeroizing::new(entry.to_uri());
        qr::encode(&uri).ok().map(|matrix| Dialog::Qr {
            title: entry.title().to_owned(),
            matrix,
        })
    }

    pub fn backup_password(bytes: Vec<u8>, pending: Import) -> Dialog {
        Dialog::BackupPassword {
            bytes,
            pending,
            password: Zeroizing::new(String::new()),
            error: None,
        }
    }

    pub fn export() -> Dialog {
        Dialog::Export(Box::new(ExportForm {
            kind: ExportKind::Backup,
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            understood: false,
            error: None,
        }))
    }

    pub fn settings(settings: &Settings) -> Dialog {
        Dialog::Settings(Box::new(SettingsForm {
            lock_minutes: settings.lock_minutes,
            clipboard_seconds: settings.clipboard_seconds,
            hide_codes: settings.hide_codes,
            current: Zeroizing::new(String::new()),
            new: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            error: None,
        }))
    }
}

impl App {
    pub(super) fn show_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.dialog.take() else {
            return;
        };
        let escape = self.job.is_none() && ctx.input(|i| i.key_pressed(Key::Escape));
        let next = egui::Modal::new(Id::unique("dialog"))
            .frame(theme::dialog())
            .show(ctx, |ui| {
                ui.set_width(WIDTH);
                match &mut dialog {
                    Dialog::Add(form) => self.add_dialog(ui, form),
                    Dialog::Edit {
                        index,
                        issuer,
                        account,
                    } => self.edit_dialog(ui, *index, issuer, account),
                    Dialog::Delete(index) => self.delete_dialog(ui, *index),
                    Dialog::Qr { title, matrix } => qr_dialog(ui, title, matrix),
                    Dialog::Preview(import) => self.preview_dialog(ui, import),
                    Dialog::BackupPassword {
                        bytes,
                        pending,
                        password,
                        error,
                    } => self.backup_password_dialog(ui, bytes, pending, password, error),
                    Dialog::Export(form) => self.export_dialog(ui, form),
                    Dialog::Google {
                        pages,
                        index,
                        skipped,
                    } => google_dialog(ui, pages, index, *skipped),
                    Dialog::Settings(form) => self.settings_dialog(ui, form),
                }
            })
            .inner;
        match next {
            Next::Keep if !escape => {
                if self.dialog.is_none() {
                    self.dialog = Some(dialog);
                }
            }
            Next::Keep | Next::Close => {}
            Next::Replace(other) => self.dialog = Some(other),
        }
    }

    fn add_dialog(&mut self, ui: &mut Ui, f: &mut AddForm) -> Next {
        let ctx = ui.ctx().clone();
        title(ui, "Add account");
        ui.horizontal(|ui| {
            if ui.button("Scan QR image").clicked() {
                if let Some(paths) = rfd::FileDialog::new()
                    .set_title("Choose a QR code image")
                    .add_filter("Images", &["png", "jpg", "jpeg", "webp", "bmp", "gif"])
                    .pick_files()
                {
                    self.import_paths(&ctx, paths);
                }
                return Next::Close;
            }
            if ui.button("Paste from clipboard").clicked() {
                self.import_clipboard(&ctx);
                return Next::Close;
            }
            Next::Keep
        })
        .inner
        .or_keep(|| {
            muted(
                ui,
                "Or paste the setup key the website shows next to its QR code.",
            );
            ui.label(RichText::new("Setup key").small().color(theme::MUTED));
            let key = ui.add(
                TextEdit::singleline(&mut *f.secret)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("JBSW Y3DP EHPK 3PXP")
                    .desired_width(f32::INFINITY),
            );
            theme::name(&key, "Setup key");
            let service = field(ui, "Name", &mut f.issuer, "GitHub", false);
            let _ = field(
                ui,
                "Account (optional)",
                &mut f.account,
                "you@example.com",
                false,
            );
            if f.focus {
                if f.secret.trim().is_empty() {
                    key.request_focus();
                } else {
                    service.request_focus();
                }
                f.focus = false;
            }
            preview(ui, f);
            ui.collapsing("Advanced", |ui| {
                egui::Grid::new("advanced")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Type");
                        egui::ComboBox::from_id_salt("kind")
                            .selected_text(if f.totp {
                                "Time based"
                            } else {
                                "Counter based"
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut f.totp, true, "Time based");
                                ui.selectable_value(&mut f.totp, false, "Counter based");
                            });
                        ui.end_row();
                        ui.label("Algorithm");
                        egui::ComboBox::from_id_salt("algorithm")
                            .selected_text(f.algorithm.name())
                            .show_ui(ui, |ui| {
                                for a in Algorithm::ALL {
                                    ui.selectable_value(&mut f.algorithm, a, a.name());
                                }
                            });
                        ui.end_row();
                        ui.label("Digits");
                        egui::ComboBox::from_id_salt("digits")
                            .selected_text(f.digits.to_string())
                            .show_ui(ui, |ui| {
                                for d in 6..=8 {
                                    ui.selectable_value(&mut f.digits, d, d.to_string());
                                }
                            });
                        ui.end_row();
                        if f.totp {
                            ui.label("Period");
                            ui.add(
                                egui::DragValue::new(&mut f.period)
                                    .range(1..=3600)
                                    .suffix(" s"),
                            );
                        } else {
                            ui.label("Counter");
                            ui.add(egui::DragValue::new(&mut f.counter));
                        }
                        ui.end_row();
                    });
            });
            show_error(ui, &f.error);
            let (cancel, ok) = actions(ui, theme::primary("Add"));
            if cancel {
                return Next::Close;
            }
            if ok {
                match self.add_from_form(f) {
                    Ok(message) => {
                        self.notify(message);
                        return Next::Close;
                    }
                    Err(e) => f.error = Some(e),
                }
            }
            Next::Keep
        })
    }

    fn add_from_form(&mut self, f: &AddForm) -> Result<String, String> {
        let typed = f.secret.trim();
        if typed.to_ascii_lowercase().starts_with("otpauth") {
            let import = transfer::from_text(typed);
            if import.entries.is_empty() {
                return Err(import
                    .problems
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "That link could not be read".to_owned()));
            }
            let added = self.add_entries(import.entries);
            return if added == 0 {
                Err("That account is already in your list".to_owned())
            } else {
                Ok(format!("Added {added}"))
            };
        }
        let entry = form_entry(f)?;
        let name = entry.title().to_owned();
        if self.add_entries(vec![entry]) == 0 {
            Err("That account is already in your list".to_owned())
        } else {
            Ok(format!("Added {name}"))
        }
    }

    fn edit_dialog(
        &mut self,
        ui: &mut Ui,
        index: usize,
        issuer: &mut String,
        account: &mut String,
    ) -> Next {
        title(ui, "Edit name");
        field(ui, "Name", issuer, "", false);
        field(ui, "Account", account, "", false);
        let (cancel, ok) = actions(ui, theme::primary("Save"));
        if cancel {
            return Next::Close;
        }
        if ok {
            if let Some(entry) = self
                .vault
                .as_mut()
                .and_then(|v| v.data.entries.get_mut(index))
            {
                entry.issuer = issuer.trim().to_owned();
                entry.account = account.trim().to_owned();
                if entry.issuer.is_empty() && entry.account.is_empty() {
                    entry.account = "Unnamed".to_owned();
                }
            }
            self.save();
            return Next::Close;
        }
        Next::Keep
    }

    fn delete_dialog(&mut self, ui: &mut Ui, index: usize) -> Next {
        let name = self
            .vault
            .as_ref()
            .and_then(|v| v.data.entries.get(index))
            .map(|e| {
                if e.subtitle().is_empty() {
                    e.title().to_owned()
                } else {
                    format!("{} ({})", e.title(), e.subtitle())
                }
            });
        let Some(name) = name else {
            return Next::Close;
        };
        title(ui, "Delete account");
        ui.label(format!("Delete {name}?"));
        muted(
            ui,
            "Make sure two-factor login is turned off for this account or that you have another copy, or you may be locked out.",
        );
        let (cancel, ok) = actions(ui, theme::danger("Delete"));
        if ok {
            if let Some(vault) = &mut self.vault
                && index < vault.data.entries.len()
            {
                vault.data.entries.remove(index);
            }
            self.save();
            self.notify("Deleted");
            return Next::Close;
        }
        if cancel { Next::Close } else { Next::Keep }
    }

    fn preview_dialog(&mut self, ui: &mut Ui, import: &mut Import) -> Next {
        let (fresh, existing): (Vec<&Entry>, Vec<&Entry>) = import.entries.iter().partition(|e| {
            !self.vault.as_ref().is_some_and(|v| {
                v.data
                    .entries
                    .iter()
                    .any(|x| x.same_key(e) && x.issuer == e.issuer && x.account == e.account)
            })
        });
        title(ui, "Import");
        if fresh.is_empty() {
            ui.label("No new accounts.");
        } else {
            ui.label(format!(
                "Found {} new account{}.",
                fresh.len(),
                if fresh.len() == 1 { "" } else { "s" }
            ));
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(ui, |ui| {
                    for entry in &fresh {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(entry.title()).strong());
                            ui.label(RichText::new(entry.subtitle()).color(theme::MUTED));
                        });
                    }
                });
        }
        if !existing.is_empty() {
            muted(ui, &format!("{} already in your list.", existing.len()));
        }
        if import.skipped > 0 {
            muted(
                ui,
                &format!(
                    "{} used a format this app does not support and were skipped.",
                    import.skipped
                ),
            );
        }
        for problem in import.problems.iter().take(5) {
            ui.label(RichText::new(problem).small().color(theme::DANGER));
        }
        if import.problems.len() > 5 {
            muted(
                ui,
                &format!("and {} more problems", import.problems.len() - 5),
            );
        }
        let count = fresh.len();
        let label = if count == 0 {
            "Close".to_owned()
        } else {
            format!("Import {count}")
        };
        let (cancel, ok) = actions(ui, theme::primary(&label));
        if ok {
            if count > 0 {
                let entries = std::mem::take(&mut import.entries);
                let added = self.add_entries(entries);
                self.notify(format!("Imported {added}"));
            }
            return Next::Close;
        }
        if cancel { Next::Close } else { Next::Keep }
    }

    fn backup_password_dialog(
        &mut self,
        ui: &mut Ui,
        bytes: &mut Vec<u8>,
        pending: &mut Import,
        password: &mut Zeroizing<String>,
        error: &mut Option<String>,
    ) -> Next {
        title(ui, "Encrypted backup");
        muted(
            ui,
            "Enter the password that was used when this backup was made.",
        );
        let response = ui.add(
            TextEdit::singleline(&mut **password)
                .password(true)
                .hint_text("Backup password")
                .desired_width(f32::INFINITY),
        );
        theme::name(&response, "Backup password");
        if !response.has_focus() && password.is_empty() && error.is_none() {
            response.request_focus();
        }
        let enter = response.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        show_error(ui, error);
        let (cancel, ok) = actions(ui, theme::primary("Open"));
        if cancel {
            return Next::Close;
        }
        if (ok || enter) && !password.is_empty() {
            let bytes = std::mem::take(bytes);
            let pending = std::mem::take(pending);
            let password = Zeroizing::new(std::mem::take(&mut **password));
            let ctx = ui.ctx().clone();
            self.spawn("Decrypting the backup", &ctx, move || {
                let result = transfer::from_bytes(&bytes, Some(&password));
                Box::new(move |app: &mut App| match result {
                    Ok(found) => {
                        let mut all = pending;
                        all.merge(found);
                        app.review(all, None);
                    }
                    Err(e) => {
                        app.dialog = Some(Dialog::BackupPassword {
                            bytes,
                            pending,
                            password: Zeroizing::new(String::new()),
                            error: Some(e.to_string()),
                        })
                    }
                })
            });
            return Next::Close;
        }
        Next::Keep
    }

    fn export_dialog(&mut self, ui: &mut Ui, f: &mut ExportForm) -> Next {
        let entries: Vec<Entry> = self
            .vault
            .as_ref()
            .map(|v| v.data.entries.clone())
            .unwrap_or_default();
        title(ui, "Export");
        ui.horizontal(|ui| {
            ui.selectable_value(&mut f.kind, ExportKind::Backup, "Encrypted backup");
            ui.selectable_value(&mut f.kind, ExportKind::Text, "Plain text");
            ui.selectable_value(&mut f.kind, ExportKind::Google, "Google Authenticator");
        });
        ui.add_space(4.0);
        if entries.is_empty() {
            muted(ui, "There is nothing to export yet.");
            let (cancel, ok) = actions(ui, theme::primary("Close"));
            return if cancel || ok {
                Next::Close
            } else {
                Next::Keep
            };
        }
        let ctx = ui.ctx().clone();
        match f.kind {
            ExportKind::Backup => {
                muted(
                    ui,
                    "A password protected file you can import here later, on this computer or another one.",
                );
                password_field(ui, &mut f.password, "Backup password");
                password_field(ui, &mut f.confirm, "Repeat password");
                show_error(ui, &f.error);
                let (cancel, ok) = actions(ui, theme::primary("Save backup"));
                if cancel {
                    return Next::Close;
                }
                if ok {
                    if f.password.chars().count() < vault::MIN_PASSWORD {
                        f.error = Some(format!("Use at least {} characters", vault::MIN_PASSWORD));
                    } else if *f.password != *f.confirm {
                        f.error = Some("The passwords do not match".to_owned());
                    } else if let Some(path) = rfd::FileDialog::new()
                        .set_title("Save backup")
                        .set_file_name(format!("meskd-auth-{}.meskd", today()))
                        .add_filter("Meskd backup", &["meskd"])
                        .save_file()
                    {
                        let password = Zeroizing::new(std::mem::take(&mut *f.password));
                        self.spawn("Encrypting the backup", &ctx, move || {
                            let result = transfer::to_backup(&entries, &password)
                                .and_then(|bytes| vault::write_atomic(&path, &bytes));
                            Box::new(move |app: &mut App| match result {
                                Ok(()) => app.notify("Backup saved"),
                                Err(e) => app.notify(format!("Could not save the backup: {e}")),
                            })
                        });
                        return Next::Close;
                    }
                }
            }
            ExportKind::Text => {
                muted(
                    ui,
                    "Standard otpauth links, one per line. Most authenticator apps can import them.",
                );
                ui.label(
                    RichText::new(
                        "The file is not encrypted. Anyone who opens it can generate your codes.",
                    )
                    .color(theme::WARN),
                );
                ui.checkbox(&mut f.understood, "I understand");
                let (cancel, ok) = actions(ui, theme::primary("Save file"));
                if cancel {
                    return Next::Close;
                }
                if ok
                    && f.understood
                    && let Some(path) = rfd::FileDialog::new()
                        .set_title("Save links")
                        .set_file_name(format!("meskd-auth-{}.txt", today()))
                        .add_filter("Text", &["txt"])
                        .save_file()
                {
                    let text = Zeroizing::new(transfer::to_uri_list(&entries));
                    match vault::write_atomic(&path, text.as_bytes()) {
                        Ok(()) => self.notify("Saved"),
                        Err(e) => self.notify(format!("Could not save: {e}")),
                    }
                    return Next::Close;
                }
            }
            ExportKind::Google => {
                muted(
                    ui,
                    "Shows QR codes on this screen. In Google Authenticator open Transfer accounts, then Import accounts, and scan them. Nothing is written to disk.",
                );
                let (cancel, ok) = actions(ui, theme::primary("Show QR codes"));
                if cancel {
                    return Next::Close;
                }
                if ok {
                    let refs: Vec<&Entry> = entries.iter().collect();
                    match migration::encode(&refs) {
                        Ok((links, skipped)) => {
                            let pages: Vec<Matrix> = links
                                .iter()
                                .filter_map(|l| qr::encode(&Zeroizing::new(l.clone())).ok())
                                .collect();
                            if pages.is_empty() {
                                f.error = Some(
                                    "None of your accounts can be moved to Google Authenticator"
                                        .to_owned(),
                                );
                            } else {
                                return Next::Replace(Dialog::Google {
                                    pages,
                                    index: 0,
                                    skipped,
                                });
                            }
                        }
                        Err(e) => f.error = Some(e.to_string()),
                    }
                }
                show_error(ui, &f.error);
            }
        }
        Next::Keep
    }

    fn settings_dialog(&mut self, ui: &mut Ui, f: &mut SettingsForm) -> Next {
        title(ui, "Settings");
        egui::Grid::new("settings")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label("Lock after");
                choice(
                    ui,
                    "lock",
                    &mut f.lock_minutes,
                    &[
                        (1, "1 minute"),
                        (5, "5 minutes"),
                        (15, "15 minutes"),
                        (60, "1 hour"),
                        (0, "Never"),
                    ],
                );
                ui.end_row();
                ui.label("Clear copied code");
                choice(
                    ui,
                    "clip",
                    &mut f.clipboard_seconds,
                    &[
                        (15, "After 15 s"),
                        (30, "After 30 s"),
                        (60, "After 1 min"),
                        (0, "Never"),
                    ],
                );
                ui.end_row();
            });
        ui.checkbox(
            &mut f.hide_codes,
            "Hide codes until the pointer is over them",
        );
        ui.add_space(4.0);
        if let Some(vault) = &self.vault {
            ui.label(
                RichText::new(format!("Vault: {}", vault.path().display()))
                    .small()
                    .color(theme::MUTED),
            );
        }
        ui.separator();
        ui.label(RichText::new("Change password").strong());
        password_field(ui, &mut f.current, "Current password");
        password_field(ui, &mut f.new, "New password");
        password_field(ui, &mut f.confirm, "Repeat new password");
        show_error(ui, &f.error);
        let change = ui.button("Change password").clicked();
        let (cancel, ok) = actions_with(ui, theme::primary("Save"), false);
        if change {
            if f.new.chars().count() < vault::MIN_PASSWORD {
                f.error = Some(format!("Use at least {} characters", vault::MIN_PASSWORD));
            } else if *f.new != *f.confirm {
                f.error = Some("The new passwords do not match".to_owned());
            } else if let Some(mut vault) = self.vault.take() {
                let current = Zeroizing::new(std::mem::take(&mut *f.current));
                let new = Zeroizing::new(std::mem::take(&mut *f.new));
                f.confirm = Zeroizing::new(String::new());
                f.error = None;
                let ctx = ui.ctx().clone();
                self.spawn("Changing the password", &ctx, move || {
                    let result = vault.change_password(&current, &new);
                    Box::new(move |app: &mut App| {
                        app.vault = Some(vault);
                        app.last_input = std::time::Instant::now();
                        match result {
                            Ok(()) => app.notify("Password changed"),
                            Err(meskd_auth::Error::Decrypt) => {
                                if let Some(Dialog::Settings(form)) = &mut app.dialog {
                                    form.error = Some("The current password is wrong".to_owned());
                                }
                            }
                            Err(e) => {
                                if let Some(Dialog::Settings(form)) = &mut app.dialog {
                                    form.error = Some(e.to_string());
                                }
                            }
                        }
                    })
                });
            }
        }
        if cancel {
            return Next::Close;
        }
        if ok {
            if let Some(vault) = &mut self.vault {
                vault.data.settings = Settings {
                    lock_minutes: f.lock_minutes,
                    clipboard_seconds: f.clipboard_seconds,
                    hide_codes: f.hide_codes,
                };
            }
            self.save();
            return Next::Close;
        }
        Next::Keep
    }
}

trait OrKeep {
    fn or_keep(self, then: impl FnOnce() -> Next) -> Next;
}

impl OrKeep for Next {
    fn or_keep(self, then: impl FnOnce() -> Next) -> Next {
        match self {
            Next::Keep => then(),
            other => other,
        }
    }
}

fn qr_dialog(ui: &mut Ui, name: &str, matrix: &Matrix) -> Next {
    title(ui, name);
    muted(
        ui,
        "Scan this with another authenticator app. Anyone who sees this code can copy the account.",
    );
    ui.vertical_centered(|ui| draw_qr(ui, matrix, 260.0));
    let (cancel, ok) = actions(ui, theme::primary("Done"));
    if cancel || ok {
        Next::Close
    } else {
        Next::Keep
    }
}

fn google_dialog(ui: &mut Ui, pages: &[Matrix], index: &mut usize, skipped: usize) -> Next {
    title(ui, "Google Authenticator");
    if pages.len() > 1 {
        muted(
            ui,
            &format!(
                "Code {} of {}. Scan them in order.",
                *index + 1,
                pages.len()
            ),
        );
    }
    ui.vertical_centered(|ui| draw_qr(ui, &pages[*index], 280.0));
    if skipped > 0 {
        muted(
            ui,
            &format!(
                "{skipped} accounts use settings Google Authenticator does not support and were left out."
            ),
        );
    }
    ui.add_space(8.0);
    let mut next = Next::Keep;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(*index > 0, egui::Button::new("Previous"))
            .clicked()
        {
            *index -= 1;
        }
        if ui
            .add_enabled(*index + 1 < pages.len(), egui::Button::new("Next"))
            .clicked()
        {
            *index += 1;
        }
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(theme::primary("Done")).clicked() {
                next = Next::Close;
            }
        });
    });
    next
}

fn draw_qr(ui: &mut Ui, matrix: &Matrix, side: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(side, side), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 8.0, Color32::WHITE);
    let quiet = 3.0;
    let cell = side / (matrix.width as f32 + quiet * 2.0);
    for y in 0..matrix.width {
        for x in 0..matrix.width {
            if matrix.is_dark(x, y) {
                let min = rect.min + vec2((x as f32 + quiet) * cell, (y as f32 + quiet) * cell);
                painter.rect_filled(
                    Rect::from_min_size(min, vec2(cell + 0.5, cell + 0.5)),
                    0.0,
                    Color32::BLACK,
                );
            }
        }
    }
}

fn title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(18.0).strong());
    ui.add_space(2.0);
}

fn muted(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::MUTED));
}

fn show_error(ui: &mut Ui, error: &Option<String>) {
    if let Some(error) = error {
        ui.label(RichText::new(error).color(theme::DANGER));
    }
}

fn form_entry(f: &AddForm) -> Result<Entry, String> {
    let typed = f.secret.trim();
    if typed.to_ascii_lowercase().starts_with("otpauth://") {
        return Entry::from_uri(typed).map_err(|e| e.to_string());
    }
    let secret = parse_secret(typed).map_err(|e| e.to_string())?;
    let kind = if f.totp {
        OtpKind::Totp { period: f.period }
    } else {
        OtpKind::Hotp { counter: f.counter }
    };
    Entry::new(&f.issuer, &f.account, secret, f.algorithm, f.digits, kind)
        .map_err(|e| e.to_string())
}

fn preview(ui: &mut Ui, f: &AddForm) {
    if f.secret.trim().is_empty() {
        return;
    }
    ui.add_space(4.0);
    match form_entry(f) {
        Ok(entry) => {
            let now = super::unix_now();
            let code = super::group(&entry.code(now));
            ui.horizontal(|ui| {
                ui.label(RichText::new("Code").small().color(theme::MUTED));
                ui.label(RichText::new(code).monospace().size(20.0));
                if let OtpKind::Totp { period } = entry.kind {
                    ui.label(
                        RichText::new(format!("{} s", meskd_auth::otp::seconds_left(now, period)))
                            .small()
                            .color(theme::MUTED),
                    );
                }
            });
            muted(
                ui,
                "If the website asks for a code to finish setup, enter this one.",
            );
        }
        Err(_) => {
            ui.label(
                RichText::new("This does not look like a setup key yet")
                    .small()
                    .color(theme::WARN),
            );
        }
    }
}

fn field(
    ui: &mut Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    password: bool,
) -> egui::Response {
    ui.label(RichText::new(label).small().color(theme::MUTED));
    let response = ui.add(
        TextEdit::singleline(value)
            .hint_text(hint.to_owned())
            .password(password)
            .char_limit(200)
            .desired_width(f32::INFINITY),
    );
    theme::name(&response, label);
    response
}

fn password_field(ui: &mut Ui, value: &mut Zeroizing<String>, hint: &str) {
    let response = ui.add(
        TextEdit::singleline(&mut **value)
            .password(true)
            .hint_text(hint.to_owned())
            .desired_width(f32::INFINITY),
    );
    theme::name(&response, hint);
}

fn choice(ui: &mut Ui, id: &str, value: &mut u32, options: &[(u32, &str)]) {
    let current = options
        .iter()
        .find(|(v, _)| v == value)
        .map(|(_, l)| l.to_string())
        .unwrap_or_else(|| value.to_string());
    egui::ComboBox::from_id_salt(id)
        .selected_text(current)
        .width(150.0)
        .show_ui(ui, |ui| {
            for (v, label) in options {
                ui.selectable_value(value, *v, *label);
            }
        });
}

fn actions(ui: &mut Ui, confirm: egui::Button<'static>) -> (bool, bool) {
    actions_with(ui, confirm, true)
}

fn actions_with(ui: &mut Ui, confirm: egui::Button<'static>, enter_confirms: bool) -> (bool, bool) {
    let enter = enter_confirms && ui.input(|i| i.key_pressed(Key::Enter));
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            let ok = ui.add(confirm).clicked() || enter;
            let cancel = ui.button("Cancel").clicked();
            (cancel, ok)
        })
        .inner
    })
    .inner
}
