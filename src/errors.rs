use std::path::Path;

use crate::domain::{Fingerprint, KeyId};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{context}: {}", io_message(.source))]
    IoPath { source: std::io::Error, context: String },

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("{} already exists (use --overwrite)", .0.display())]
    FileExists(std::path::PathBuf),

    #[error("wrong password (decryption failed)")]
    WrongPassword,

    #[error("password cannot be empty")]
    PasswordEmpty,

    #[error("passwords don't match")]
    PasswordMismatch,

    #[error("password is too long (max {max} bytes)")]
    PasswordTooLong { max: usize },

    #[error("password is not valid UTF-8")]
    PasswordNotUtf8,

    #[error("cannot prompt for a password: {source}; use --password-stdin or --password-file when no terminal is available")]
    PasswordPrompt { source: std::io::Error },

    #[error("key ID mismatch: signature has {sig_id}, public key has {pk_id}")]
    KeyIdMismatch { sig_id: KeyId, pk_id: KeyId },

    #[error("signed by key {signer}, but the public key is {public_key}")]
    SignerMismatch { signer: Fingerprint, public_key: Fingerprint },

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("cannot determine home directory (is $HOME set?)")]
    HomeDirNotFound,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
}

fn io_message(err: &std::io::Error) -> std::borrow::Cow<'static, str> {
    match err.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".into(),
        std::io::ErrorKind::PermissionDenied => "permission denied".into(),
        std::io::ErrorKind::AlreadyExists => "already exists".into(),
        _ => err.to_string().into(),
    }
}

pub trait IoContext<T> {
    fn io_context(self, path: &Path) -> Result<T, Error>;
}

impl<T> IoContext<T> for Result<T, std::io::Error> {
    fn io_context(self, path: &Path) -> Result<T, Error> {
        self.map_err(|source| Error::IoPath {
            context: path.display().to_string(),
            source,
        })
    }
}
