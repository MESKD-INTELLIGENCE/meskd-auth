use crate::entry::{Entry, OtpKind};
use crate::error::{Error, Result};
use crate::migration;
use crate::qr;
use crate::vault::{self, KdfParams, VaultData};

#[derive(Debug, Default)]
pub struct Import {
    pub entries: Vec<Entry>,
    pub skipped: usize,
    pub problems: Vec<String>,
}

impl Import {
    fn push(&mut self, entry: Entry) {
        let seen = self
            .entries
            .iter()
            .any(|e| e.same_key(&entry) && e.issuer == entry.issuer && e.account == entry.account);
        if !seen {
            self.entries.push(entry);
        }
    }

    pub fn merge(&mut self, other: Import) {
        for entry in other.entries {
            self.push(entry);
        }
        self.skipped += other.skipped;
        self.problems.extend(other.problems);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub fn needs_password(bytes: &[u8]) -> bool {
    vault::is_sealed(bytes)
}

pub fn from_text(text: &str) -> Import {
    let mut import = Import::default();
    let text = text.trim_start_matches('\u{feff}');
    let normalized = text
        .replace("\\/", "/")
        .replace("\\u0026", "&")
        .replace("\\u002F", "/")
        .replace("&amp;", "&");
    for entry in json_entries(&normalized) {
        import.push(entry);
    }
    for (n, link) in find_links(&normalized).into_iter().enumerate() {
        let item = n + 1;
        if migration::is_migration(link) {
            match migration::parse(link) {
                Ok(batch) => {
                    import.skipped += batch.skipped;
                    for entry in batch.entries {
                        import.push(entry);
                    }
                }
                Err(e) => import.problems.push(format!("item {item}: {e}")),
            }
        } else {
            match Entry::from_uri(link) {
                Ok(entry) => import.push(entry),
                Err(e) => import.problems.push(format!("item {item}: {e}")),
            }
        }
    }
    import
}

pub fn from_bytes(bytes: &[u8], password: Option<&str>) -> Result<Import> {
    if vault::is_sealed(bytes) {
        let data = vault::unseal(bytes, password.unwrap_or_default())?;
        let mut import = Import::default();
        for entry in data.entries.iter().cloned() {
            import.push(entry);
        }
        return Ok(import);
    }
    if image::guess_format(bytes).is_ok() {
        let texts = qr::decode_file_bytes(bytes)?;
        return finish(from_text(&texts.join("\n")));
    }
    let text = decode_text(bytes).ok_or(Error::NothingToImport)?;
    finish(from_text(&text))
}

fn decode_text(bytes: &[u8]) -> Option<String> {
    let decode_utf16 = |data: &[u8], little: bool| {
        let mut units = Vec::with_capacity(data.len() / 2);
        let mut at = 0;
        while at + 1 < data.len() {
            let pair = [data[at], data[at + 1]];
            units.push(if little {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            });
            at += 2;
        }
        String::from_utf16(&units)
            .ok()
            .map(|s| s.trim_start_matches('\u{feff}').to_owned())
    };
    if bytes.starts_with(&[0xff, 0xfe]) {
        return decode_utf16(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return decode_utf16(&bytes[2..], false);
    }
    std::str::from_utf8(bytes)
        .ok()
        .map(|s| s.trim_start_matches('\u{feff}').to_owned())
}

fn json_entries(text: &str) -> Vec<Entry> {
    let trimmed = text.trim_start_matches(|c: char| c.is_whitespace());
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_json(&value, &mut found);
    found
}

fn walk_json(value: &serde_json::Value, found: &mut Vec<Entry>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(entry) = aegis_entry(map).or_else(|| bitwarden_entry(map)) {
                found.push(entry);
            }
            for child in map.values() {
                walk_json(child, found);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                walk_json(child, found);
            }
        }
        _ => {}
    }
}

fn aegis_entry(map: &serde_json::Map<String, serde_json::Value>) -> Option<Entry> {
    use serde_json::Value;
    let info = map.get("info")?.as_object()?;
    let secret = crate::entry::parse_secret(info.get("secret")?.as_str()?).ok()?;
    let issuer = map
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let account = map.get("name").and_then(Value::as_str).unwrap_or_default();
    let algorithm = info
        .get("algo")
        .and_then(Value::as_str)
        .and_then(|a| crate::entry::Algorithm::parse(a).ok())
        .unwrap_or_default();
    let digits = info.get("digits").and_then(Value::as_u64).unwrap_or(6) as u32;
    let kind = if map.get("type").and_then(Value::as_str) == Some("hotp") {
        OtpKind::Hotp {
            counter: info.get("counter").and_then(Value::as_u64).unwrap_or(0),
        }
    } else {
        OtpKind::Totp {
            period: info.get("period").and_then(Value::as_u64).unwrap_or(30) as u32,
        }
    };
    Entry::new(issuer, account, secret, algorithm, digits, kind).ok()
}

fn bitwarden_entry(map: &serde_json::Map<String, serde_json::Value>) -> Option<Entry> {
    use serde_json::Value;
    let login = map.get("login")?.as_object()?;
    let totp = login.get("totp").and_then(Value::as_str)?.trim();
    if totp.is_empty() || totp.to_ascii_lowercase().contains("otpauth") {
        return None;
    }
    let secret = crate::entry::parse_secret(totp).ok()?;
    let issuer = map.get("name").and_then(Value::as_str).unwrap_or_default();
    let account = login
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Entry::new(
        issuer,
        account,
        secret,
        crate::entry::Algorithm::Sha1,
        6,
        OtpKind::default(),
    )
    .ok()
}

pub fn from_qr_texts(texts: &[String]) -> Result<Import> {
    finish(from_text(&texts.join("\n")))
}

fn finish(import: Import) -> Result<Import> {
    if import.entries.is_empty() && import.problems.is_empty() && import.skipped == 0 {
        Err(Error::NothingToImport)
    } else {
        Ok(import)
    }
}

pub fn to_uri_list(entries: &[Entry]) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&entry.to_uri());
        out.push('\n');
    }
    out
}

pub fn to_backup(entries: &[Entry], password: &str) -> Result<Vec<u8>> {
    let data = VaultData {
        entries: entries.to_vec(),
        settings: Default::default(),
    };
    vault::seal(&data, password, KdfParams::default())
}

fn find_links(text: &str) -> Vec<&str> {
    let lower = text.to_ascii_lowercase();
    let mut links = Vec::new();
    let mut from = 0;
    while let Some(found) = lower[from..].find("otpauth") {
        let start = from + found;
        let rest = &lower[start..];
        if !(rest.starts_with("otpauth://") || rest.starts_with("otpauth-migration://")) {
            from = start + 7;
            continue;
        }
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`'))
            .map_or(text.len(), |i| start + i);
        links.push(&text[start..end]);
        from = end;
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Algorithm, OtpKind};

    fn entry(issuer: &str, secret: &[u8]) -> Entry {
        Entry::new(
            issuer,
            "me",
            secret.to_vec(),
            Algorithm::Sha1,
            6,
            OtpKind::default(),
        )
        .unwrap()
    }

    #[test]
    fn plain_link_list_round_trip() {
        let entries = vec![entry("A", b"aaaaaaaaaa"), entry("B", b"bbbbbbbbbb")];
        let text = to_uri_list(&entries);
        let import = from_text(&text);
        assert_eq!(import.entries.len(), 2);
        assert!(import.problems.is_empty());
        assert!(import.entries[1].same_key(&entries[1]));
    }

    #[test]
    fn links_are_found_inside_csv_and_json() {
        let csv = "name,totp\nGitHub,\"otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\"\n";
        assert_eq!(from_text(csv).entries.len(), 1);
        let json = r#"{"uri":"otpauth:\/\/totp\/X:me?secret=JBSWY3DPEHPK3PXP&issuer=X"}"#;
        let import = from_text(json);
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.entries[0].issuer, "X");
    }

    #[test]
    fn bad_lines_are_reported_without_secrets() {
        let text =
            "otpauth://totp/ok?secret=JBSWY3DPEHPK3PXP\notpauth://totp/bad?secret=SUPERSECRET1\n";
        let import = from_text(text);
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.problems.len(), 1);
        assert!(import.problems[0].starts_with("item 2"));
        assert!(!import.problems[0].contains("SUPERSECRET"));
    }

    #[test]
    fn duplicate_links_import_once() {
        let line = "otpauth://totp/A:me?secret=JBSWY3DPEHPK3PXP\n";
        assert_eq!(from_text(&line.repeat(3)).entries.len(), 1);
    }

    #[test]
    fn google_export_text_is_recognised() {
        let a = entry("G", b"gggggggggg");
        let (links, _) = migration::encode(&[&a]).unwrap();
        let import = from_bytes(links[0].as_bytes(), None).unwrap();
        assert_eq!(import.entries.len(), 1);
        assert!(import.entries[0].same_key(&a));
    }

    #[test]
    fn encrypted_backup_round_trip() {
        let entries = vec![entry("A", b"aaaaaaaaaa")];
        let bytes = to_backup(&entries, "backup password").unwrap();
        assert!(needs_password(&bytes));
        assert!(matches!(
            from_bytes(&bytes, Some("wrong password")),
            Err(Error::Decrypt)
        ));
        assert!(from_bytes(&bytes, None).is_err());
        let import = from_bytes(&bytes, Some("backup password")).unwrap();
        assert_eq!(import.entries.len(), 1);
    }

    #[test]
    fn qr_image_file_is_imported() {
        let a = entry("Q", b"qqqqqqqqqq");
        let (links, _) = migration::encode(&[&a]).unwrap();
        let matrix = qr::encode(&links[0]).unwrap();
        let scale = 6u32;
        let side = (matrix.width as u32 + 8) * scale;
        let img = image::GrayImage::from_fn(side, side, |x, y| {
            let mx = (x / scale) as i64 - 4;
            let my = (y / scale) as i64 - 4;
            let on = mx >= 0
                && my >= 0
                && (mx as usize) < matrix.width
                && (my as usize) < matrix.width
                && matrix.is_dark(mx as usize, my as usize);
            image::Luma([if on { 0 } else { 255 }])
        });
        let mut png = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        let import = from_bytes(&png, None).unwrap();
        assert_eq!(import.entries.len(), 1);
        assert!(import.entries[0].same_key(&a));
    }

    #[test]
    fn bitwarden_json_with_a_bare_totp_secret() {
        let json = r#"{"items":[{"name":"GitHub","login":{"username":"octo","totp":"JBSWY3DPEHPK3PXP"}},{"name":"No 2fa","login":{"username":"x","totp":null}}]}"#;
        let import = from_text(json);
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.entries[0].issuer, "GitHub");
        assert_eq!(import.entries[0].account, "octo");
        assert_eq!(import.entries[0].secret_base32(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn aegis_json_export() {
        let json = r#"{"version":1,"header":{"slots":[]},"db":{"entries":[
            {"type":"totp","name":"ops","issuer":"Cloudflare","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA256","digits":8,"period":60}},
            {"type":"hotp","name":"bank","issuer":"","info":{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algo":"SHA1","digits":6,"counter":7}}
        ]}}"#;
        let import = from_text(json);
        assert_eq!(import.entries.len(), 2);
        assert_eq!(import.entries[0].issuer, "Cloudflare");
        assert_eq!(import.entries[0].algorithm, Algorithm::Sha256);
        assert_eq!(import.entries[0].digits, 8);
        assert_eq!(import.entries[0].kind, OtpKind::Totp { period: 60 });
        assert_eq!(import.entries[1].issuer, "bank");
        assert_eq!(import.entries[1].kind, OtpKind::Hotp { counter: 7 });
    }

    #[test]
    fn windows_utf16_text_files_are_read() {
        let text = "otpauth://totp/Utf16:me?secret=JBSWY3DPEHPK3PXP&issuer=Utf16";
        let mut bytes = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let import = from_bytes(&bytes, None).unwrap();
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.entries[0].issuer, "Utf16");
    }

    #[test]
    fn html_escaped_links_are_read() {
        let import = from_text("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=Big&amp;Co");
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.entries[0].issuer, "Big&Co");
    }

    #[test]
    fn unrelated_files_say_nothing_was_found() {
        assert!(matches!(
            from_bytes(b"hello world", None),
            Err(Error::NothingToImport)
        ));
        assert!(matches!(
            from_bytes(&[0xff, 0xfe, 0x00, 0x81], None),
            Err(Error::NothingToImport)
        ));
        assert!(from_text("otpauthotpauth otpauth:/x").entries.is_empty());
    }
}
