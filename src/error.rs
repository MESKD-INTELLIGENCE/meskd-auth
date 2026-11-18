use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the secret is not valid base32")]
    InvalidSecret,
    #[error("the secret is empty")]
    EmptySecret,
    #[error("not an otpauth link")]
    NotOtpAuth,
    #[error("unsupported code type: {0}")]
    UnsupportedKind(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("digits must be 6, 7 or 8")]
    InvalidDigits,
    #[error("period must be between 1 and 3600 seconds")]
    InvalidPeriod,
    #[error("the link is malformed: {0}")]
    MalformedUri(&'static str),
    #[error("the Google Authenticator export is damaged: {0}")]
    MalformedMigration(&'static str),
    #[error("no QR code found in the image")]
    NoQrCode,
    #[error("the image could not be read: {0}")]
    Image(String),
    #[error("the data does not fit in a QR code")]
    QrTooLarge,
    #[error("wrong password, or the file is damaged")]
    Decrypt,
    #[error("this is not a Meskd Authenticator file")]
    NotAVault,
    #[error("this file was made by a newer version (format {0})")]
    UnsupportedVersion(u8),
    #[error("the file asks for unreasonable key derivation settings")]
    KdfParams,
    #[error("the password is too short, use at least {0} characters")]
    PasswordTooShort(usize),
    #[error("a vault already exists at this location")]
    VaultExists,
    #[error("nothing to import was found")]
    NothingToImport,
    #[error("no secure random source is available")]
    Random,
    #[error("the vault contents are damaged: {0}")]
    Corrupt(String),
    #[error("{0}")]
    Io(#[from] io::Error),
}
