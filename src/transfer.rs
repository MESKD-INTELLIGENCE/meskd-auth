use crate::entry::Entry;
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
    let normalized = text.replace("\\/", "/").replace("\\u0026", "&");
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
    let text = std::str::from_utf8(bytes).map_err(|_| Error::NothingToImport)?;
    finish(from_text(text))
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
