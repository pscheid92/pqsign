use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::util::{resolve_key_path, resolve_signature_path};
use crate::errors::{Error, IoContext};
use crate::format;
use crate::password;

pub struct Options {
    pub file: PathBuf,
    pub secret_key: Option<PathBuf>,
    pub sig_file: Option<PathBuf>,
    pub trusted_comment: Option<String>,
    pub password: Option<Zeroizing<String>>,
}

pub fn run(opts: Options) -> Result<(), Error> {
    let Options {
        file,
        secret_key,
        sig_file,
        trusted_comment,
        password,
    } = opts;
    let secret_key_path = resolve_key_path(secret_key, "default.key")?;
    let signature_path = resolve_signature_path(sig_file, &file)?;

    // Validate input file before prompting for password
    std::fs::metadata(&file).io_context(&file)?;

    let secret_key = format::read_secret_key_with(&secret_key_path, |_kdf| match password {
        Some(pw) => Ok(pw),
        None => password::read_password("Password: "),
    })?;

    let trusted = build_trusted_comment(&file, trusted_comment.as_deref());
    let signature = secret_key.sign(&file, &trusted)?;

    format::write_signature(&signature_path, &signature)?;
    eprintln!("Signature:  {}", signature_path.display());
    eprintln!("Secret key: {}", secret_key_path.display());

    Ok(())
}

fn build_trusted_comment(file: &Path, comment: Option<&str>) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match comment {
        Some(c) => format!("timestamp:{ts}\tfile:{}\t{c}", file.display()),
        None => format!("timestamp:{ts}\tfile:{}", file.display()),
    }
}
