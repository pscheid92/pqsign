use std::path::PathBuf;

use super::util::{resolve_key_path, resolve_signature_path};
use crate::errors::{Error, IoContext};
use crate::format;

pub struct Options {
    pub file: PathBuf,
    pub public_key: Option<PathBuf>,
    pub public_key_string: Option<String>,
    pub sig_file: Option<PathBuf>,
    pub quiet: bool,
}

pub fn run(opts: Options) -> Result<(), Error> {
    let Options {
        file,
        public_key,
        public_key_string,
        sig_file,
        quiet,
    } = opts;
    let signature_path = resolve_signature_path(sig_file, &file)?;

    // Validate input file before doing any key/signature I/O
    std::fs::metadata(&file).io_context(&file)?;

    let (public_key, pk_source) = match public_key_string {
        Some(s) => (format::read_public_key_string(&s)?, "<inline>".to_string()),
        None => {
            let path = resolve_key_path(public_key, "default.key.pub")?;
            let pk = format::read_public_key(&path)?;
            (pk, path.display().to_string())
        }
    };

    let signature = format::read_signature(&signature_path)?;

    if let Err(e) = signature.verify(&public_key, &file) {
        if !quiet {
            eprintln!("Public key: {pk_source}");
            eprintln!("Signature:  {}", signature_path.display());
        }
        return Err(e);
    }

    if !quiet {
        println!("Signature: OK");
        println!("Trusted comment: {}", signature.trusted_comment);
        println!("Public key: {pk_source}");
        println!("Fingerprint: {}", public_key.fingerprint());
    }

    Ok(())
}
