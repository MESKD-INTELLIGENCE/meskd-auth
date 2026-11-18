use std::time::{Duration, Instant};

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use meskd_auth::transfer::Import;
use meskd_auth::{Algorithm, Entry, KdfParams, OtpKind, Vault};
use zeroize::Zeroizing;

use super::dialogs::Dialog;
use super::{App, Config, bare_key, group, today};

const FAST: KdfParams = KdfParams {
    m_cost: 64,
    t_cost: 1,
    p_cost: 1,
};

fn harness(path: std::path::PathBuf) -> Harness<'static, App> {
    let app = App::new(Config { path, params: FAST });
    let mut h = Harness::builder()
        .with_size(egui::vec2(440.0, 640.0))
        .build_ui_state(|ui, app: &mut App| app.frame(ui), app);
    h.run_steps(2);
    h
}

fn settle(h: &mut Harness<'static, App>) {
    let start = Instant::now();
    while h.state().job.is_some() && start.elapsed() < Duration::from_secs(20) {
        h.step();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(h.state().job.is_none(), "background work did not finish");
    h.run_steps(3);
}

fn sample(issuer: &str) -> Entry {
    Entry::new(
        issuer,
        "me@example.com",
        b"0123456789".to_vec(),
        Algorithm::Sha1,
        6,
        OtpKind::default(),
    )
    .unwrap()
}

fn unlocked(dir: &tempfile::TempDir) -> Harness<'static, App> {
    let path = dir.path().join("vault.meskd");
    let mut h = harness(path);
    h.state_mut().password = Zeroizing::new("correct horse".to_owned());
    h.state_mut().confirm = Zeroizing::new("correct horse".to_owned());
    h.run_steps(1);
    h.get_by_label("Create vault").click();
    h.run_steps(1);
    settle(&mut h);
    assert!(h.state().vault.is_some());
    h
}

#[test]
fn first_run_creates_an_encrypted_vault() {
    let dir = tempfile::tempdir().unwrap();
    let h = unlocked(&dir);
    assert!(dir.path().join("vault.meskd").exists());
    h.get_by_label("No accounts yet");
    assert!(h.state().password.is_empty());
}

#[test]
fn setup_rejects_mismatched_and_short_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness(dir.path().join("vault.meskd"));
    h.state_mut().password = Zeroizing::new("short".to_owned());
    h.state_mut().confirm = Zeroizing::new("short".to_owned());
    h.run_steps(1);
    h.get_by_label("Create vault").click();
    h.run_steps(2);
    h.get_by_label_contains("at least 8");
    h.state_mut().password = Zeroizing::new("long enough one".to_owned());
    h.state_mut().confirm = Zeroizing::new("long enough two".to_owned());
    h.run_steps(1);
    h.get_by_label("Create vault").click();
    h.run_steps(2);
    h.get_by_label("The passwords do not match");
    assert!(!dir.path().join("vault.meskd").exists());
}

#[test]
fn unlock_reports_a_wrong_password_and_accepts_the_right_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.meskd");
    let mut vault = Vault::create(&path, "correct horse", FAST).unwrap();
    vault.data.add(sample("GitHub"));
    vault.save().unwrap();
    drop(vault);

    let mut h = harness(path);
    h.get_by_label("Unlock");
    h.state_mut().password = Zeroizing::new("wrong horse".to_owned());
    h.run_steps(1);
    h.get_by_label("Unlock").click();
    h.run_steps(1);
    settle(&mut h);
    assert!(h.state().vault.is_none());
    h.get_by_label_contains("wrong password");

    h.state_mut().password = Zeroizing::new("correct horse".to_owned());
    h.run_steps(1);
    h.get_by_label("Unlock").click();
    h.run_steps(1);
    settle(&mut h);
    assert!(h.state().vault.is_some());
    h.get_by_label("GitHub");
    h.get_by_label("me@example.com");
}

#[test]
fn adding_an_account_by_setup_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.get_by_label("Add").click();
    h.run_steps(2);
    let Some(Dialog::Add(form)) = &mut h.state_mut().dialog else {
        panic!("add dialog did not open");
    };
    form.issuer = "Proton".to_owned();
    form.account = "ops".to_owned();
    *form.secret = "jbsw y3dp ehpk 3pxp".to_owned();
    h.run_steps(1);
    h.key_press(egui::Key::Enter);
    h.run_steps(2);
    assert!(h.state().dialog.is_none());
    let entries = &h.state().vault.as_ref().unwrap().data.entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].issuer, "Proton");
    assert_eq!(entries[0].secret_base32(), "JBSWY3DPEHPK3PXP");

    drop(h);
    let reopened = Vault::open(&dir.path().join("vault.meskd"), "correct horse").unwrap();
    assert_eq!(reopened.data.entries.len(), 1);
}

#[test]
fn a_bad_setup_key_shows_an_error_and_keeps_the_dialog() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut().dialog = Some(Dialog::add());
    h.run_steps(1);
    let Some(Dialog::Add(form)) = &mut h.state_mut().dialog else {
        unreachable!()
    };
    form.issuer = "X".to_owned();
    *form.secret = "not base32 1890".to_owned();
    h.run_steps(1);
    h.key_press(egui::Key::Enter);
    h.run_steps(2);
    assert!(matches!(h.state().dialog, Some(Dialog::Add(_))));
    h.get_by_label("the secret is not valid base32");
    assert!(h.state().vault.as_ref().unwrap().data.entries.is_empty());
}

#[test]
fn pasting_an_otpauth_link_into_the_key_field_works() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut().dialog = Some(Dialog::add());
    h.run_steps(1);
    let Some(Dialog::Add(form)) = &mut h.state_mut().dialog else {
        unreachable!()
    };
    *form.secret = "otpauth://totp/Linear:me?secret=JBSWY3DPEHPK3PXP&issuer=Linear".to_owned();
    h.run_steps(1);
    h.key_press(egui::Key::Enter);
    h.run_steps(2);
    assert_eq!(
        h.state().vault.as_ref().unwrap().data.entries[0].issuer,
        "Linear"
    );
}

#[test]
fn import_preview_adds_only_new_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut().add_entries(vec![sample("Existing")]);
    let import = Import {
        entries: vec![sample("Existing"), sample("Fresh")],
        skipped: 1,
        problems: vec!["item 3: the secret is empty".to_owned()],
    };
    h.state_mut().review(import, None);
    h.run_steps(2);
    h.get_by_label("Found 1 new account.");
    h.get_by_label("1 already in your list.");
    h.get_by_label("item 3: the secret is empty");
    h.get_by_label("Import 1").click();
    h.run_steps(2);
    let names: Vec<String> = h
        .state()
        .vault
        .as_ref()
        .unwrap()
        .data
        .entries
        .iter()
        .map(|e| e.issuer.clone())
        .collect();
    assert_eq!(names, ["Existing", "Fresh"]);
}

#[test]
fn deleting_asks_first() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut()
        .add_entries(vec![sample("Doomed"), sample("Kept")]);
    h.state_mut().dialog = Some(Dialog::Delete(0));
    h.run_steps(2);
    h.get_by_label("Delete Doomed (me@example.com)?");
    h.get_by_label("Cancel").click();
    h.run_steps(2);
    assert_eq!(h.state().vault.as_ref().unwrap().data.entries.len(), 2);
    h.state_mut().dialog = Some(Dialog::Delete(0));
    h.run_steps(2);
    h.get_by_label("Delete").click();
    h.run_steps(2);
    let entries = &h.state().vault.as_ref().unwrap().data.entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].issuer, "Kept");
}

#[test]
fn search_filters_the_list() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut()
        .add_entries(vec![sample("GitHub"), sample("Cloudflare")]);
    h.state_mut().search = "cloud".to_owned();
    h.run_steps(2);
    h.get_by_label("Cloudflare");
    assert!(h.query_by_label("GitHub").is_none());
    h.state_mut().search = "zzz".to_owned();
    h.run_steps(2);
    h.get_by_label("No matches");
}

#[test]
fn hidden_codes_are_masked() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut().add_entries(vec![sample("Masked")]);
    h.state_mut()
        .vault
        .as_mut()
        .unwrap()
        .data
        .settings
        .hide_codes = true;
    h.run_steps(2);
    h.get_by_label("\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}");
}

#[test]
fn lock_shortcut_and_inactivity_both_lock() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::L);
    h.run_steps(2);
    assert!(h.state().vault.is_none());
    h.get_by_label("Unlock");

    let mut h = unlocked(&tempfile::tempdir().unwrap());
    h.state_mut()
        .vault
        .as_mut()
        .unwrap()
        .data
        .settings
        .lock_minutes = 1;
    h.state_mut().last_input = Instant::now() - Duration::from_secs(61);
    h.step();
    assert!(h.state().vault.is_none());
}

#[test]
fn hotp_next_code_advances_and_saves() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    let hotp = Entry::new(
        "Bank",
        "me",
        b"12345678901234567890".to_vec(),
        Algorithm::Sha1,
        6,
        OtpKind::Hotp { counter: 0 },
    )
    .unwrap();
    h.state_mut().add_entries(vec![hotp]);
    h.run_steps(2);
    h.get_by_label("755 224");
    h.get_by_label("Next").click();
    h.run_steps(2);
    h.get_by_label("287 082");
    drop(h);
    let vault = Vault::open(&dir.path().join("vault.meskd"), "correct horse").unwrap();
    assert_eq!(vault.data.entries[0].kind, OtpKind::Hotp { counter: 1 });
}

#[test]
fn encrypted_backup_import_asks_for_its_password() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    let bytes = meskd_auth::vault::seal(
        &meskd_auth::VaultData {
            entries: vec![sample("FromBackup")],
            settings: Default::default(),
        },
        "backup password",
        FAST,
    )
    .unwrap();
    h.state_mut().review(Import::default(), Some(bytes));
    h.run_steps(2);
    h.get_by_label("Encrypted backup");
    let Some(Dialog::BackupPassword { password, .. }) = &mut h.state_mut().dialog else {
        panic!("password dialog missing")
    };
    **password = "not it at all".to_owned();
    h.run_steps(1);
    h.get_by_label("Open").click();
    h.run_steps(1);
    settle(&mut h);
    h.get_by_label("wrong password, or the file is damaged");
    let Some(Dialog::BackupPassword { password, .. }) = &mut h.state_mut().dialog else {
        panic!("password dialog missing")
    };
    **password = "backup password".to_owned();
    h.run_steps(1);
    h.get_by_label("Open").click();
    h.run_steps(1);
    settle(&mut h);
    h.get_by_label("Import 1").click();
    h.run_steps(2);
    assert_eq!(
        h.state().vault.as_ref().unwrap().data.entries[0].issuer,
        "FromBackup"
    );
}

#[test]
fn a_second_window_cannot_open_the_same_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.meskd");
    let _first = harness(path.clone());
    let second = harness(path);
    second.get_by_label("Already open");
}

#[test]
fn bare_setup_keys_are_recognised() {
    assert!(bare_key("JBSW Y3DP EHPK 3PXP").is_some());
    assert!(bare_key("  jbswy3dpehpk3pxp\n").is_some());
    assert!(bare_key("JBSW-Y3DP-EHPK-3PXP-JBSW-Y3DP").is_some());
    assert!(bare_key("JBSWY3DP").is_none());
    assert!(bare_key("hello there, this is a sentence").is_none());
    assert!(bare_key("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").is_none());
}

#[test]
fn pasting_a_bare_key_opens_add_with_a_live_code() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    let ctx = h.ctx.clone();
    h.state_mut().import_text(
        &ctx,
        Zeroizing::new("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ".to_owned()),
    );
    h.run_steps(2);
    let Some(Dialog::Add(form)) = &h.state().dialog else {
        panic!("add dialog did not open");
    };
    assert_eq!(&**form.secret, "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ");
    h.get_by_label("Code");
    let now = super::unix_now();
    let shown = [now.saturating_sub(30), now, now + 30].iter().any(|t| {
        let code = meskd_auth::otp::totp(b"12345678901234567890", *t, 30, Algorithm::Sha1, 6);
        h.query_by_label(&group(&code)).is_some()
    });
    assert!(shown, "the live code was not shown");
    h.get_by_label("If the website asks for a code to finish setup, enter this one.");
    h.key_press(egui::Key::Enter);
    h.run_steps(2);
    let entries = &h.state().vault.as_ref().unwrap().data.entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].account, "Unnamed");
}

#[test]
fn invalid_keys_warn_before_adding() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut().dialog = Some(Dialog::add_with_key(Zeroizing::new(
        "not a key!".to_owned(),
    )));
    h.run_steps(2);
    h.get_by_label("This does not look like a setup key yet");
}

#[test]
fn delete_all_asks_first_and_then_clears_everything() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut()
        .add_entries(vec![sample("One"), sample("Two")]);
    h.state_mut().dialog = Some(Dialog::DeleteAll(2));
    h.run_steps(2);
    h.get_by_label("Delete all 2 accounts?");
    h.get_by_label("Cancel").click();
    h.run_steps(2);
    assert_eq!(h.state().vault.as_ref().unwrap().data.entries.len(), 2);
    h.state_mut().dialog = Some(Dialog::DeleteAll(2));
    h.run_steps(2);
    h.get_by_label("Delete all").click();
    h.run_steps(2);
    assert!(h.state().vault.as_ref().unwrap().data.entries.is_empty());
    assert!(h.state().dialog.is_none());
    drop(h);
    let reopened = Vault::open(&dir.path().join("vault.meskd"), "correct horse").unwrap();
    assert!(reopened.data.entries.is_empty());
}

#[test]
fn rows_show_a_plain_countdown_in_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = unlocked(&dir);
    h.state_mut().add_entries(vec![sample("Ticking")]);
    h.run_steps(2);
    let now = super::unix_now();
    let plausible: Vec<String> = [0u64, 1, 2]
        .iter()
        .map(|back| super::countdown(meskd_auth::otp::seconds_left(now.saturating_sub(*back), 30)))
        .collect();
    assert!(
        plausible
            .iter()
            .any(|label| h.query_by_label(label.as_str()).is_some()),
        "no countdown label among {plausible:?}"
    );
}

#[test]
fn codes_are_grouped_for_reading() {
    assert_eq!(group("123456"), "123 456");
    assert_eq!(group("1234567"), "123 4567");
    assert_eq!(group("12345678"), "1234 5678");
    assert_eq!(group("12"), "12");
}

#[test]
fn today_is_an_iso_date() {
    let d = today();
    assert_eq!(d.len(), 10);
    assert_eq!(&d[4..5], "-");
    assert_eq!(&d[7..8], "-");
    assert!(d[..4].parse::<u32>().unwrap() >= 2024);
}
