use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Argon2, Params};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entry::Entry;
use crate::error::{Error, Result};

const MAGIC: &[u8; 8] = b"MSKDAUTH";
const FORMAT: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + 1 + 12 + SALT_LEN + NONCE_LEN;
const MAX_FILE: u64 = 64 * 1024 * 1024;
pub const MIN_PASSWORD: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const MAX_M_COST: u32 = 1024 * 1024;
    pub const MAX_T_COST: u32 = 16;
    pub const MAX_P_COST: u32 = 8;

    fn check(self) -> Result<()> {
        let sane = (1..=Self::MAX_T_COST).contains(&self.t_cost)
            && (1..=Self::MAX_P_COST).contains(&self.p_cost)
            && self.m_cost >= 8 * self.p_cost
            && self.m_cost <= Self::MAX_M_COST;
        if sane { Ok(()) } else { Err(Error::KdfParams) }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub lock_minutes: u32,
    pub clipboard_seconds: u32,
    pub hide_codes: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            lock_minutes: 5,
            clipboard_seconds: 30,
            hide_codes: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub settings: Settings,
}

impl VaultData {
    pub fn add(&mut self, entry: Entry) -> bool {
        let duplicate = self
            .entries
            .iter()
            .any(|e| e.same_key(&entry) && e.issuer == entry.issuer && e.account == entry.account);
        if !duplicate {
            self.entries.push(entry);
        }
        !duplicate
    }
}

pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
    pub data: VaultData,
}

impl Vault {
    pub fn default_path() -> Option<PathBuf> {
        let folder = if cfg!(windows) {
            "Meskd Authenticator"
        } else {
            "meskd-auth"
        };
        dirs::data_dir().map(|d| d.join(folder).join("vault.meskd"))
    }

    pub fn create(path: &Path, password: &str, params: KdfParams) -> Result<Vault> {
        if path.exists() {
            return Err(Error::VaultExists);
        }
        check_password(password)?;
        params.check()?;
        let salt = random_array::<SALT_LEN>()?;
        let key = derive_key(password, &salt, params)?;
        let vault = Vault {
            path: path.to_path_buf(),
            key,
            salt,
            params,
            data: VaultData::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: &Path, password: &str) -> Result<Vault> {
        let bytes = read_limited(path)?;
        let header = Header::parse(&bytes)?;
        let key = derive_key(password, &header.salt, header.params)?;
        let data = decrypt(&key, &header, &bytes)?;
        Ok(Vault {
            path: path.to_path_buf(),
            key,
            salt: header.salt,
            params: header.params,
            data,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<()> {
        let bytes = encrypt(&self.key, &self.salt, self.params, &self.data)?;
        write_atomic(&self.path, &bytes)
    }

    pub fn change_password(&mut self, current: &str, new: &str) -> Result<()> {
        let check = derive_key(current, &self.salt, self.params)?;
        if *check != *self.key {
            return Err(Error::Decrypt);
        }
        check_password(new)?;
        let params = KdfParams::default().max_with(self.params);
        let salt = random_array::<SALT_LEN>()?;
        let key = derive_key(new, &salt, params)?;
        let old = (
            std::mem::replace(&mut self.key, key),
            self.salt,
            self.params,
        );
        self.salt = salt;
        self.params = params;
        if let Err(e) = self.save() {
            self.key = old.0;
            self.salt = old.1;
            self.params = old.2;
            return Err(e);
        }
        Ok(())
    }
}

impl KdfParams {
    fn max_with(self, other: KdfParams) -> KdfParams {
        KdfParams {
            m_cost: self.m_cost.max(other.m_cost),
            t_cost: self.t_cost.max(other.t_cost),
            p_cost: self.p_cost.max(other.p_cost),
        }
    }
}

pub fn seal(data: &VaultData, password: &str, params: KdfParams) -> Result<Vec<u8>> {
    check_password(password)?;
    params.check()?;
    let salt = random_array::<SALT_LEN>()?;
    let key = derive_key(password, &salt, params)?;
    encrypt(&key, &salt, params, data)
}

pub fn unseal(bytes: &[u8], password: &str) -> Result<VaultData> {
    let header = Header::parse(bytes)?;
    let key = derive_key(password, &header.salt, header.params)?;
    decrypt(&key, &header, bytes)
}

pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub fn acquire_lock(vault_path: &Path) -> Result<Option<File>> {
    let lock_path = vault_path.with_extension("lock");
    if let Some(dir) = lock_path.parent() {
        create_private_dir(dir)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

pub fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let len = fs::metadata(path)?.len();
    if len > MAX_FILE {
        return Err(Error::NotAVault);
    }
    Ok(fs::read(path)?)
}

fn check_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD {
        Err(Error::PasswordTooShort(MIN_PASSWORD))
    } else {
        Ok(())
    }
}

struct Header {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn parse(bytes: &[u8]) -> Result<Header> {
        if !bytes.starts_with(MAGIC) {
            return Err(Error::NotAVault);
        }
        if bytes.len() < HEADER_LEN + 16 {
            return Err(Error::Decrypt);
        }
        let version = bytes[MAGIC.len()];
        if version != FORMAT {
            return Err(Error::UnsupportedVersion(version));
        }
        let at = MAGIC.len() + 1;
        let word = |i: usize| {
            u32::from_le_bytes(
                bytes[at + i * 4..at + i * 4 + 4]
                    .try_into()
                    .expect("4 bytes"),
            )
        };
        let params = KdfParams {
            m_cost: word(0),
            t_cost: word(1),
            p_cost: word(2),
        };
        params.check()?;
        let salt_at = at + 12;
        let nonce_at = salt_at + SALT_LEN;
        Ok(Header {
            params,
            salt: bytes[salt_at..nonce_at].try_into().expect("salt length"),
            nonce: bytes[nonce_at..HEADER_LEN]
                .try_into()
                .expect("nonce length"),
        })
    }

    fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT);
        out.extend_from_slice(&self.params.m_cost.to_le_bytes());
        out.extend_from_slice(&self.params.t_cost.to_le_bytes());
        out.extend_from_slice(&self.params.p_cost.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out
    }
}

fn derive_key(password: &str, salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    params.check()?;
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| Error::KdfParams)?;
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::KdfParams)?;
    Ok(key)
}

fn encrypt(
    key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    data: &VaultData,
) -> Result<Vec<u8>> {
    let header = Header {
        params,
        salt: *salt,
        nonce: random_array::<NONCE_LEN>()?,
    };
    let mut out = header.write();
    let plain =
        Zeroizing::new(serde_json::to_vec(data).map_err(|e| Error::Corrupt(e.to_string()))?);
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let sealed = cipher
        .encrypt(
            &XNonce::from(header.nonce),
            Payload {
                msg: &plain,
                aad: &out,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn decrypt(key: &[u8; 32], header: &Header, bytes: &[u8]) -> Result<VaultData> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(header.nonce),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &bytes[..HEADER_LEN],
                },
            )
            .map_err(|_| Error::Decrypt)?,
    );
    let data: VaultData =
        serde_json::from_slice(&plain).map_err(|e| Error::Corrupt(e.to_string()))?;
    for entry in &data.entries {
        entry.validate()?;
    }
    Ok(data)
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Random)?;
    Ok(out)
}

fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        create_private_dir(dir)?;
    }
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Algorithm, OtpKind};

    const FAST: KdfParams = KdfParams {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
    };

    fn sample() -> Entry {
        Entry::new(
            "Meskd",
            "ops@meskd.com",
            b"0123456789".to_vec(),
            Algorithm::Sha1,
            6,
            OtpKind::default(),
        )
        .unwrap()
    }

    #[test]
    fn create_save_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("vault.meskd");
        let mut vault = Vault::create(&path, "correct horse", FAST).unwrap();
        vault.data.add(sample());
        vault.data.settings.hide_codes = true;
        vault.save().unwrap();
        drop(vault);

        let reopened = Vault::open(&path, "correct horse").unwrap();
        assert_eq!(reopened.data.entries.len(), 1);
        assert!(reopened.data.entries[0].same_key(&sample()));
        assert!(reopened.data.settings.hide_codes);
        assert!(!path.with_file_name("vault.meskd.tmp").exists());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.meskd");
        Vault::create(&path, "correct horse", FAST).unwrap();
        assert!(matches!(
            Vault::open(&path, "wrong horse"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn refuses_to_overwrite_and_short_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.meskd");
        assert!(matches!(
            Vault::create(&path, "short", FAST),
            Err(Error::PasswordTooShort(_))
        ));
        Vault::create(&path, "long enough", FAST).unwrap();
        assert!(matches!(
            Vault::create(&path, "long enough", FAST),
            Err(Error::VaultExists)
        ));
    }

    #[test]
    fn plaintext_never_hits_the_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.meskd");
        let mut vault = Vault::create(&path, "correct horse", FAST).unwrap();
        vault.data.add(sample());
        vault.save().unwrap();
        let raw = fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains("Meskd\""));
        assert!(!text.contains("ops@meskd.com"));
        assert!(!text.contains(&sample().secret_base32()));
    }

    #[test]
    fn every_byte_is_authenticated() {
        let mut data = VaultData::default();
        data.add(sample());
        let sealed = seal(&data, "correct horse", FAST).unwrap();
        assert_eq!(unseal(&sealed, "correct horse").unwrap().entries.len(), 1);
        for i in MAGIC.len() + 13..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x01;
            assert!(
                unseal(&bad, "correct horse").is_err(),
                "byte {i} was not protected"
            );
        }
        assert!(unseal(&sealed[..sealed.len() - 1], "correct horse").is_err());
    }

    #[test]
    fn hostile_headers_are_refused_before_hashing() {
        let mut data = VaultData::default();
        data.add(sample());
        let sealed = seal(&data, "correct horse", FAST).unwrap();
        let mut huge = sealed.clone();
        huge[MAGIC.len() + 1..MAGIC.len() + 5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            unseal(&huge, "correct horse"),
            Err(Error::KdfParams)
        ));
        let mut slow = sealed.clone();
        slow[MAGIC.len() + 5..MAGIC.len() + 9].copy_from_slice(&1000u32.to_le_bytes());
        assert!(matches!(
            unseal(&slow, "correct horse"),
            Err(Error::KdfParams)
        ));
        let mut future = sealed.clone();
        future[MAGIC.len()] = 9;
        assert!(matches!(
            unseal(&future, "correct horse"),
            Err(Error::UnsupportedVersion(9))
        ));
        assert!(matches!(
            unseal(b"hello", "correct horse"),
            Err(Error::NotAVault)
        ));
        assert!(matches!(
            unseal(MAGIC, "correct horse"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn each_save_uses_a_fresh_nonce() {
        let data = VaultData::default();
        let a = seal(&data, "correct horse", FAST).unwrap();
        let b = seal(&data, "correct horse", FAST).unwrap();
        assert_ne!(
            a[HEADER_LEN - NONCE_LEN..HEADER_LEN],
            b[HEADER_LEN - NONCE_LEN..HEADER_LEN]
        );
        assert_ne!(a, b);
    }

    #[test]
    fn change_password_requires_the_current_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.meskd");
        let mut vault = Vault::create(&path, "first password", FAST).unwrap();
        vault.data.add(sample());
        vault.save().unwrap();
        assert!(matches!(
            vault.change_password("nope nope", "second password"),
            Err(Error::Decrypt)
        ));
        vault
            .change_password("first password", "second password")
            .unwrap();
        drop(vault);
        assert!(Vault::open(&path, "first password").is_err());
        let vault = Vault::open(&path, "second password").unwrap();
        assert_eq!(vault.data.entries.len(), 1);
        assert_eq!(vault.params, KdfParams::default());
    }

    #[test]
    fn duplicates_are_not_added_twice() {
        let mut data = VaultData::default();
        assert!(data.add(sample()));
        assert!(!data.add(sample()));
        assert_eq!(data.entries.len(), 1);
    }

    #[test]
    fn only_one_window_can_hold_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.meskd");
        let first = acquire_lock(&path).unwrap();
        assert!(first.is_some());
        assert!(acquire_lock(&path).unwrap().is_none());
        drop(first);
        assert!(acquire_lock(&path).unwrap().is_some());
    }

    #[test]
    fn default_parameters_are_accepted() {
        assert!(KdfParams::default().check().is_ok());
    }
}
