use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::util::{resolve_key_path, resolve_signature_path, with_suffix};
use crate::domain::SignatureFormat;
use crate::errors::{Error, IoContext};
use crate::format;
use crate::password::PasswordSource;
use crate::terminal::SafePath;

pub struct Options {
    pub file: PathBuf,
    pub secret_key: Option<PathBuf>,
    pub sig_file: Option<PathBuf>,
    pub trusted_comment: Option<String>,
    pub password: PasswordSource,
    pub format: SignatureFormat,
}

pub fn run(opts: Options) -> Result<(), Error> {
    let Options {
        file,
        secret_key,
        sig_file,
        trusted_comment,
        password,
        format,
    } = opts;
    let secret_key_path = resolve_key_path(secret_key, "default.key")?;
    let signature_path = resolve_signature_path(sig_file, &file)?;

    // Validate the input file and the comment before asking for the password
    std::fs::metadata(&file).io_context(&file)?;
    check_signature_path(&signature_path, &file, &secret_key_path)?;
    let trusted = build_trusted_comment(&file, trusted_comment.as_deref());
    format::check_trusted_comment(&trusted)?;
    warn_if_accessible_by_others(&secret_key_path);

    let secret_key = format::read_secret_key_with(&secret_key_path, |_kdf| password.read_existing())?;
    let signature = secret_key.sign_as(&file, &trusted, format)?;

    format::write_signature(&signature_path, &signature)?;
    eprintln!("Signature:  {}", SafePath(&signature_path));
    eprintln!("Secret key: {}", SafePath(&secret_key_path));

    Ok(())
}

/// Refuses a signature path that names the file being signed or one of the key files, which the signature would
/// replace.
fn check_signature_path(signature: &Path, file: &Path, secret_key: &Path) -> Result<(), Error> {
    let public_key = with_suffix(secret_key, ".pub");
    let protected = [
        ("the file being signed", file),
        ("the secret key", secret_key),
        ("the public key", &public_key),
    ];

    if let Some((what, path)) = protected.into_iter().find(|(_, path)| is_same_file(signature, path)) {
        let err = Error::WouldOverwrite {
            what,
            path: path.to_path_buf(),
        };
        return Err(err);
    }
    Ok(())
}

/// Whether both paths name the same existing file, also through symlinks and, on Unix, hard links.
fn is_same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(a), Ok(b)) => (a.dev(), a.ino()) == (b.dev(), b.ino()),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Secret keys are encrypted, so this warns instead of refusing like ssh does. Keys written by pqsign 0.1
/// with `generate --overwrite` could be left readable by everyone.
fn warn_if_accessible_by_others(secret_key_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::metadata(secret_key_path) else { return };
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            let path = SafePath(secret_key_path);
            eprintln!("warning: secret key {path} is accessible by other users (mode {mode:04o}); restrict it with: chmod 600 {path}");
        }
    }
    #[cfg(not(unix))]
    let _ = secret_key_path;
}

/// `timestamp:<unix time>\tfile:<file name>`, then a tab and the user's comment if there is one. The file name
/// is the base name only, so signatures do not reveal where the file was signed, and it is escaped so odd file
/// names cannot break the comment's rules or add fields.
fn build_trusted_comment(file: &Path, comment: Option<&str>) -> String {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let name = format::escape_file_name(file.file_name().unwrap_or(file.as_os_str()));

    match comment {
        Some(c) => format!("timestamp:{ts}\tfile:{name}\t{c}"),
        None => format!("timestamp:{ts}\tfile:{name}"),
    }
}
