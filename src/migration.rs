use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use zeroize::Zeroize;

use crate::entry::{Algorithm, Entry, OtpKind};
use crate::error::{Error, Result};

const PREFIX: &str = "otpauth-migration://offline?";
const MAX_PER_CODE: usize = 10;

#[derive(Debug, Default)]
pub struct Batch {
    pub entries: Vec<Entry>,
    pub skipped: usize,
    pub index: u32,
    pub size: u32,
}

pub fn is_migration(text: &str) -> bool {
    text.trim()
        .get(..PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(PREFIX))
}

pub fn parse(uri: &str) -> Result<Batch> {
    let uri = uri.trim();
    if !is_migration(uri) {
        return Err(Error::MalformedMigration("not a migration link"));
    }
    let query = &uri[PREFIX.len()..];
    let data = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("data="))
        .ok_or(Error::MalformedMigration("missing data"))?;
    let mut text = percent_decode_str(data)
        .decode_utf8()
        .map_err(|_| Error::MalformedMigration("data is not text"))?
        .replace(' ', "+");
    text.retain(|c| !c.is_whitespace());
    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&text).ok());
    text.zeroize();
    let mut bytes = decoded.ok_or(Error::MalformedMigration("data is not base64"))?;
    let result = decode_payload(&bytes);
    bytes.zeroize();
    result
}

pub fn encode(entries: &[&Entry]) -> Result<(Vec<String>, usize)> {
    let usable: Vec<&Entry> = entries.iter().copied().filter(|e| exportable(e)).collect();
    let skipped = entries.len() - usable.len();
    if usable.is_empty() {
        return Ok((Vec::new(), skipped));
    }
    let mut id_bytes = [0u8; 4];
    getrandom::fill(&mut id_bytes).map_err(|_| Error::Random)?;
    let batch_id = i32::from_le_bytes(id_bytes) & 0x7fff_ffff;
    let chunks: Vec<&[&Entry]> = usable.chunks(MAX_PER_CODE).collect();
    let size = chunks.len() as u64;
    let mut links = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let mut payload = Vec::new();
        for entry in chunk.iter() {
            let mut params = encode_entry(entry);
            put_bytes(&mut payload, 1, &params);
            params.zeroize();
        }
        put_varint_field(&mut payload, 2, 1);
        put_varint_field(&mut payload, 3, size);
        put_varint_field(&mut payload, 4, index as u64);
        put_varint_field(&mut payload, 5, batch_id as u64);
        let mut b64 = STANDARD.encode(&payload);
        payload.zeroize();
        links.push(format!(
            "{PREFIX}data={}",
            utf8_percent_encode(&b64, NON_ALPHANUMERIC)
        ));
        b64.zeroize();
    }
    Ok((links, skipped))
}

pub fn exportable(entry: &Entry) -> bool {
    let digits_ok = entry.digits == 6 || entry.digits == 8;
    let kind_ok = match entry.kind {
        OtpKind::Totp { period } => period == 30,
        OtpKind::Hotp { .. } => true,
    };
    digits_ok && kind_ok
}

fn encode_entry(entry: &Entry) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, 1, entry.secret());
    put_bytes(&mut out, 2, entry.account.as_bytes());
    put_bytes(&mut out, 3, entry.issuer.as_bytes());
    let algorithm = match entry.algorithm {
        Algorithm::Sha1 => 1,
        Algorithm::Sha256 => 2,
        Algorithm::Sha512 => 3,
    };
    put_varint_field(&mut out, 4, algorithm);
    put_varint_field(&mut out, 5, if entry.digits == 8 { 2 } else { 1 });
    match entry.kind {
        OtpKind::Hotp { counter } => {
            put_varint_field(&mut out, 6, 1);
            put_varint_field(&mut out, 7, counter);
        }
        OtpKind::Totp { .. } => put_varint_field(&mut out, 6, 2),
    }
    out
}

fn decode_payload(bytes: &[u8]) -> Result<Batch> {
    let mut batch = Batch {
        size: 1,
        ..Batch::default()
    };
    let mut reader = Reader::new(bytes);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Value::Bytes(params)) => match decode_entry(params) {
                Ok(entry) => batch.entries.push(entry),
                Err(_) => batch.skipped += 1,
            },
            (3, Value::Varint(size)) => batch.size = size as u32,
            (4, Value::Varint(index)) => batch.index = index as u32,
            _ => {}
        }
    }
    if batch.entries.is_empty() && batch.skipped == 0 {
        return Err(Error::NothingToImport);
    }
    Ok(batch)
}

fn decode_entry(bytes: &[u8]) -> Result<Entry> {
    let mut secret = Vec::new();
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6;
    let mut hotp = false;
    let mut counter = 0u64;

    let mut reader = Reader::new(bytes);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Value::Bytes(v)) => secret = v.to_vec(),
            (2, Value::Bytes(v)) => name = String::from_utf8_lossy(v).into_owned(),
            (3, Value::Bytes(v)) => issuer = String::from_utf8_lossy(v).into_owned(),
            (4, Value::Varint(v)) => {
                algorithm = match v {
                    0 | 1 => Algorithm::Sha1,
                    2 => Algorithm::Sha256,
                    3 => Algorithm::Sha512,
                    _ => {
                        secret.zeroize();
                        return Err(Error::UnsupportedAlgorithm("MD5".to_owned()));
                    }
                }
            }
            (5, Value::Varint(v)) => digits = if v == 2 { 8 } else { 6 },
            (6, Value::Varint(v)) => hotp = v == 1,
            (7, Value::Varint(v)) => counter = v,
            _ => {}
        }
    }

    let (issuer, account) = match (issuer.is_empty(), name.split_once(':')) {
        (true, Some((prefix, rest))) => (prefix.trim().to_owned(), rest.trim().to_owned()),
        (false, Some((prefix, rest))) if prefix.trim() == issuer.trim() => {
            (issuer, rest.trim().to_owned())
        }
        _ => (issuer, name),
    };
    let kind = if hotp {
        OtpKind::Hotp { counter }
    } else {
        OtpKind::Totp { period: 30 }
    };
    Entry::new(&issuer, &account, secret, algorithm, digits, kind)
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Skipped,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .data
                .get(self.pos)
                .ok_or(Error::MalformedMigration("truncated number"))?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::MalformedMigration("number too long"))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or(Error::MalformedMigration("truncated field"))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn next_field(&mut self) -> Result<Option<(u64, Value<'a>)>> {
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let value = match key & 7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Skipped
            }
            2 => {
                let len = usize::try_from(self.varint()?)
                    .map_err(|_| Error::MalformedMigration("field too long"))?;
                Value::Bytes(self.take(len)?)
            }
            5 => {
                self.take(4)?;
                Value::Skipped
            }
            _ => return Err(Error::MalformedMigration("unknown field type")),
        };
        Ok(Some((key >> 3, value)))
    }
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn put_varint_field(out: &mut Vec<u8>, field: u64, value: u64) {
    put_varint(out, field << 3);
    put_varint(out, value);
}

fn put_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    put_varint(out, (field << 3) | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link_for(payload: &[u8]) -> String {
        format!(
            "{PREFIX}data={}",
            utf8_percent_encode(&STANDARD.encode(payload), NON_ALPHANUMERIC)
        )
    }

    fn sample_payload() -> Vec<u8> {
        let mut inner = vec![0x0a, 0x0a];
        inner.extend_from_slice(b"Hello!\xde\xad\xbe\xef");
        inner.extend_from_slice(&[0x12, 0x18]);
        inner.extend_from_slice(b"Example:alice@google.com");
        inner.extend_from_slice(&[0x1a, 0x07]);
        inner.extend_from_slice(b"Example");
        inner.extend_from_slice(&[0x20, 0x01, 0x28, 0x01, 0x30, 0x02]);
        assert_eq!(inner.len(), 0x35);
        let mut payload = vec![0x0a, 0x35];
        payload.extend_from_slice(&inner);
        payload.extend_from_slice(&[0x10, 0x01, 0x18, 0x01, 0x20, 0x00, 0x28, 0x7b]);
        payload
    }

    #[test]
    fn decodes_a_hand_built_google_export() {
        let batch = parse(&link_for(&sample_payload())).unwrap();
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.skipped, 0);
        assert_eq!(batch.size, 1);
        let entry = &batch.entries[0];
        assert_eq!(entry.issuer, "Example");
        assert_eq!(entry.account, "alice@google.com");
        assert_eq!(entry.secret_base32(), "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.kind, OtpKind::Totp { period: 30 });
    }

    #[test]
    fn accepts_unescaped_and_url_safe_data() {
        let payload = sample_payload();
        let raw = format!("{PREFIX}data={}", STANDARD.encode(&payload));
        assert_eq!(parse(&raw).unwrap().entries.len(), 1);
        let spaced = raw.replace('+', " ");
        assert_eq!(parse(&spaced).unwrap().entries.len(), 1);
        let url_safe = format!("{PREFIX}data={}", URL_SAFE_NO_PAD.encode(&payload));
        assert_eq!(parse(&url_safe).unwrap().entries.len(), 1);
    }

    #[test]
    fn md5_entries_are_skipped_not_fatal() {
        let mut inner = vec![0x0a, 0x02, 0x01, 0x02, 0x12, 0x01, b'x', 0x20, 0x04];
        let good = sample_payload();
        let mut payload = good.clone();
        payload.push(0x0a);
        payload.push(inner.len() as u8);
        payload.append(&mut inner);
        let batch = parse(&link_for(&payload)).unwrap();
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.skipped, 1);
    }

    #[test]
    fn round_trip_through_encode() {
        let a = Entry::new(
            "GitHub",
            "me",
            b"abcdefghij".to_vec(),
            Algorithm::Sha1,
            6,
            OtpKind::default(),
        )
        .unwrap();
        let b = Entry::new(
            "",
            "Bank:me",
            vec![9; 20],
            Algorithm::Sha256,
            8,
            OtpKind::Hotp { counter: 300 },
        )
        .unwrap();
        let odd = Entry::new(
            "Odd",
            "x",
            vec![1; 10],
            Algorithm::Sha1,
            7,
            OtpKind::default(),
        )
        .unwrap();
        let (links, skipped) = encode(&[&a, &b, &odd]).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(skipped, 1);
        let batch = parse(&links[0]).unwrap();
        assert_eq!(batch.entries.len(), 2);
        assert!(batch.entries[0].same_key(&a));
        assert_eq!(batch.entries[0].issuer, "GitHub");
        assert!(batch.entries[1].same_key(&b));
        assert_eq!(batch.entries[1].issuer, "Bank");
        assert_eq!(batch.entries[1].account, "me");
        assert_eq!(batch.entries[1].kind, OtpKind::Hotp { counter: 300 });
    }

    #[test]
    fn large_exports_are_split_into_batches() {
        let entries: Vec<Entry> = (0..23)
            .map(|i| {
                Entry::new(
                    "S",
                    &format!("u{i}"),
                    vec![i as u8 + 1; 10],
                    Algorithm::Sha1,
                    6,
                    OtpKind::default(),
                )
                .unwrap()
            })
            .collect();
        let refs: Vec<&Entry> = entries.iter().collect();
        let (links, _) = encode(&refs).unwrap();
        assert_eq!(links.len(), 3);
        let mut total = 0;
        for (i, link) in links.iter().enumerate() {
            let batch = parse(link).unwrap();
            assert_eq!(batch.index as usize, i);
            assert_eq!(batch.size, 3);
            total += batch.entries.len();
        }
        assert_eq!(total, 23);
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        assert!(parse("otpauth-migration://offline?foo=bar").is_err());
        assert!(parse("otpauth-migration://offline?data=%%%").is_err());
        assert!(parse(&link_for(&[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f])).is_err());
        assert!(parse(&link_for(&[0xff; 12])).is_err());
        assert!(parse(&link_for(&[0x0b])).is_err());
        assert!(parse(&link_for(&[])).is_err());
        for len in 0..sample_payload().len() {
            let _ = parse(&link_for(&sample_payload()[..len]));
        }
    }
}
