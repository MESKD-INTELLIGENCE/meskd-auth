use std::fmt;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::otp;

const LABEL_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'@');

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub const ALL: [Algorithm; 3] = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512];

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            _ => Err(Error::UnsupportedAlgorithm(value.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OtpKind {
    Totp { period: u32 },
    Hotp { counter: u64 },
}

impl OtpKind {
    pub fn is_totp(self) -> bool {
        matches!(self, OtpKind::Totp { .. })
    }
}

impl Default for OtpKind {
    fn default() -> Self {
        OtpKind::Totp { period: 30 }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    #[serde(serialize_with = "secret_out", deserialize_with = "secret_in")]
    secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub kind: OtpKind,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"<hidden>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .finish()
    }
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.issuer == other.issuer
            && self.account == other.account
            && self.secret == other.secret
            && self.algorithm == other.algorithm
            && self.digits == other.digits
            && self.kind == other.kind
    }
}

impl Entry {
    pub fn new(
        issuer: &str,
        account: &str,
        secret: Vec<u8>,
        algorithm: Algorithm,
        digits: u32,
        kind: OtpKind,
    ) -> Result<Self> {
        let mut entry = Entry {
            id: new_id()?,
            issuer: clean_text(issuer),
            account: clean_text(account),
            secret,
            algorithm,
            digits,
            kind,
        };
        entry.validate()?;
        if entry.issuer.is_empty() && entry.account.is_empty() {
            entry.account = "Unnamed".to_owned();
        }
        Ok(entry)
    }

    pub fn validate(&self) -> Result<()> {
        if self.secret.is_empty() {
            return Err(Error::EmptySecret);
        }
        if !(6..=8).contains(&self.digits) {
            return Err(Error::InvalidDigits);
        }
        if let OtpKind::Totp { period } = self.kind
            && !(1..=3600).contains(&period)
        {
            return Err(Error::InvalidPeriod);
        }
        Ok(())
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn secret_base32(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.secret)
    }

    pub fn same_key(&self, other: &Entry) -> bool {
        self.secret == other.secret
            && self.algorithm == other.algorithm
            && self.digits == other.digits
            && self.kind.is_totp() == other.kind.is_totp()
    }

    pub fn title(&self) -> &str {
        if self.issuer.is_empty() {
            &self.account
        } else {
            &self.issuer
        }
    }

    pub fn subtitle(&self) -> &str {
        if self.issuer.is_empty() {
            ""
        } else {
            &self.account
        }
    }

    pub fn code(&self, unix_time: u64) -> String {
        match self.kind {
            OtpKind::Totp { period } => {
                otp::totp(&self.secret, unix_time, period, self.algorithm, self.digits)
            }
            OtpKind::Hotp { counter } => {
                otp::hotp(&self.secret, counter, self.algorithm, self.digits)
            }
        }
    }

    pub fn advance_counter(&mut self) {
        if let OtpKind::Hotp { counter } = &mut self.kind {
            *counter = counter.saturating_add(1);
        }
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        let uri = uri.trim();
        let rest = strip_prefix_ignore_case(uri, "otpauth://").ok_or(Error::NotOtpAuth)?;
        let (kind_name, rest) = rest
            .split_once('/')
            .ok_or(Error::MalformedUri("missing label"))?;
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = decode_component(label, false)?;

        let mut secret = None;
        let mut issuer_param = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        let mut counter = None;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = decode_component(value, true)?;
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(parse_secret(&value)?),
                "issuer" => issuer_param = Some(value),
                "algorithm" => algorithm = Algorithm::parse(&value)?,
                "digits" => {
                    digits = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::MalformedUri("digits is not a number"))?
                }
                "period" => {
                    period = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::MalformedUri("period is not a number"))?
                }
                "counter" => {
                    counter = Some(
                        value
                            .trim()
                            .parse()
                            .map_err(|_| Error::MalformedUri("counter is not a number"))?,
                    )
                }
                _ => {}
            }
        }

        let kind = match kind_name.to_ascii_lowercase().as_str() {
            "totp" => OtpKind::Totp { period },
            "hotp" => OtpKind::Hotp {
                counter: counter.unwrap_or(0),
            },
            other => return Err(Error::UnsupportedKind(other.to_owned())),
        };

        let issuer_param = issuer_param.filter(|i| !i.trim().is_empty());
        let prefixed = issuer_param.as_deref().and_then(|issuer| {
            label
                .strip_prefix(issuer)
                .and_then(|rest| rest.strip_prefix(':'))
        });
        let (label_issuer, account) = match (prefixed, label.split_once(':')) {
            (Some(rest), _) => (String::new(), rest.trim().to_owned()),
            (None, Some((issuer, account))) => {
                (issuer.trim().to_owned(), account.trim().to_owned())
            }
            (None, None) => (String::new(), label.trim().to_owned()),
        };
        let issuer = issuer_param.unwrap_or(label_issuer);
        let secret = secret.ok_or(Error::EmptySecret)?;

        Entry::new(&issuer, &account, secret, algorithm, digits, kind)
    }

    pub fn to_uri(&self) -> String {
        let account = utf8_percent_encode(&self.account, LABEL_SET);
        let label = if self.issuer.is_empty() {
            account.to_string()
        } else {
            format!(
                "{}:{}",
                utf8_percent_encode(&self.issuer, LABEL_SET),
                account
            )
        };
        let mut uri = format!(
            "otpauth://{}/{}?secret={}",
            if self.kind.is_totp() { "totp" } else { "hotp" },
            label,
            self.secret_base32()
        );
        if !self.issuer.is_empty() {
            uri.push_str("&issuer=");
            uri.push_str(&utf8_percent_encode(&self.issuer, LABEL_SET).to_string());
        }
        uri.push_str(&format!(
            "&algorithm={}&digits={}",
            self.algorithm.name(),
            self.digits
        ));
        match self.kind {
            OtpKind::Totp { period } => uri.push_str(&format!("&period={period}")),
            OtpKind::Hotp { counter } => uri.push_str(&format!("&counter={counter}")),
        }
        uri
    }
}

pub fn parse_secret(input: &str) -> Result<Vec<u8>> {
    let mut cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(Error::EmptySecret);
    }
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned);
    cleaned.zeroize();
    match decoded {
        Some(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => Err(Error::InvalidSecret),
    }
}

pub fn new_id() -> Result<String> {
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn clean_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(200)
        .collect()
}

fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

fn decode_component(value: &str, plus_is_space: bool) -> Result<String> {
    let value = if plus_is_space {
        value.replace('+', " ")
    } else {
        value.to_owned()
    };
    percent_decode_str(&value)
        .decode_utf8()
        .map(|v| v.into_owned())
        .map_err(|_| Error::MalformedUri("text is not valid UTF-8"))
}

fn secret_out<S: Serializer>(secret: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error> {
    let mut encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret);
    let result = serializer.serialize_str(&encoded);
    encoded.zeroize();
    result
}

fn secret_in<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error> {
    let mut encoded = String::deserialize(deserializer)?;
    let result = parse_secret(&encoded).map_err(serde::de::Error::custom);
    encoded.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_totp_link() {
        let entry = Entry::from_uri(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(entry.issuer, "ACME Co");
        assert_eq!(entry.account, "john.doe@email.com");
        assert_eq!(entry.algorithm, Algorithm::Sha256);
        assert_eq!(entry.digits, 8);
        assert_eq!(entry.kind, OtpKind::Totp { period: 60 });
        assert_eq!(entry.secret_base32(), "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ");
    }

    #[test]
    fn defaults_apply_when_parameters_are_missing() {
        let entry = Entry::from_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(entry.issuer, "");
        assert_eq!(entry.account, "alice");
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.kind, OtpKind::Totp { period: 30 });
    }

    #[test]
    fn issuer_parameter_wins_over_label_prefix() {
        let entry =
            Entry::from_uri("otpauth://totp/Old:bob?secret=JBSWY3DPEHPK3PXP&issuer=New").unwrap();
        assert_eq!(entry.issuer, "New");
        assert_eq!(entry.account, "bob");
    }

    #[test]
    fn hotp_links_keep_their_counter() {
        let entry = Entry::from_uri(
            "otpauth://hotp/Svc:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=5",
        )
        .unwrap();
        assert_eq!(entry.kind, OtpKind::Hotp { counter: 5 });
        assert_eq!(entry.code(0), "254676");
    }

    #[test]
    fn scheme_and_parameters_are_case_insensitive() {
        let entry =
            Entry::from_uri("OTPAUTH://TOTP/x?SECRET=jbswy3dpehpk3pxp&Algorithm=sha512").unwrap();
        assert_eq!(entry.algorithm, Algorithm::Sha512);
        assert_eq!(entry.secret_base32(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn rejects_bad_links() {
        assert!(matches!(
            Entry::from_uri("https://example.com"),
            Err(Error::NotOtpAuth)
        ));
        assert!(matches!(
            Entry::from_uri("otpauth://totp/x"),
            Err(Error::EmptySecret)
        ));
        assert!(matches!(
            Entry::from_uri("otpauth://totp/x?secret=!!!"),
            Err(Error::InvalidSecret)
        ));
        assert!(matches!(
            Entry::from_uri("otpauth://totp/x?secret=JBSWY3DP&digits=12"),
            Err(Error::InvalidDigits)
        ));
        assert!(matches!(
            Entry::from_uri("otpauth://totp/x?secret=JBSWY3DP&period=0"),
            Err(Error::InvalidPeriod)
        ));
        assert!(matches!(
            Entry::from_uri("otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5"),
            Err(Error::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            Entry::from_uri("otpauth://steam/x?secret=JBSWY3DP"),
            Err(Error::UnsupportedKind(_))
        ));
    }

    #[test]
    fn link_round_trip_keeps_everything() {
        let original = Entry::new(
            "Big & Small: Co",
            "name+tag@example.com",
            b"secret-bytes-here".to_vec(),
            Algorithm::Sha512,
            7,
            OtpKind::Totp { period: 45 },
        )
        .unwrap();
        let parsed = Entry::from_uri(&original.to_uri()).unwrap();
        assert_eq!(parsed.issuer, original.issuer);
        assert_eq!(parsed.account, original.account);
        assert!(parsed.same_key(&original));
        assert_eq!(parsed.kind, original.kind);
    }

    #[test]
    fn secrets_accept_spaces_dashes_padding_and_lowercase() {
        let expected = parse_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(parse_secret("jbsw y3dp-ehpk 3pxp").unwrap(), expected);
        assert_eq!(parse_secret("JBSWY3DPEHPK3PXP====").unwrap(), expected);
        assert!(matches!(parse_secret("  "), Err(Error::EmptySecret)));
        assert!(matches!(parse_secret("0189"), Err(Error::InvalidSecret)));
    }

    #[test]
    fn debug_output_hides_the_secret() {
        let entry = Entry::from_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        let shown = format!("{entry:?}");
        assert!(!shown.contains("JBSWY3DPEHPK3PXP"));
        assert!(shown.contains("<hidden>"));
    }

    #[test]
    fn serde_round_trip() {
        let entry =
            Entry::from_uri("otpauth://hotp/A:b?secret=JBSWY3DPEHPK3PXP&counter=9").unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let back: Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
    }

    #[test]
    fn control_characters_are_stripped_from_names() {
        let entry = Entry::new(
            " Ev\u{0}il\n ",
            "a\u{7}b",
            vec![1, 2, 3],
            Algorithm::Sha1,
            6,
            OtpKind::default(),
        )
        .unwrap();
        assert_eq!(entry.issuer, "Evil");
        assert_eq!(entry.account, "ab");
    }
}
