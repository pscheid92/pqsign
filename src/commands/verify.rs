use std::path::PathBuf;

use super::util::{DEFAULT_SECRET_KEY, PUBLIC_KEY_SUFFIX, check_input_file, resolve_key_path, resolve_signature_path};
use crate::domain::SignatureFormat;
use crate::errors::Error;
use crate::format;
use crate::terminal::SafePath;

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
    check_input_file(&file)?;

    let (public_key, pk_source) = match public_key_string {
        Some(s) => (format::read_public_key_string(&s)?, "<inline>".to_string()),
        None => {
            let path = resolve_key_path(public_key, &format!("{DEFAULT_SECRET_KEY}{PUBLIC_KEY_SUFFIX}"))?;
            let pk = format::read_public_key(&path)?;
            (pk, SafePath(&path).to_string())
        }
    };

    let signature = format::read_signature(&signature_path)?;

    if let Err(e) = signature.verify(&public_key, &file) {
        if !quiet {
            eprintln!("Public key: {pk_source}");
            eprintln!("Signature:  {}", SafePath(&signature_path));
        }
        return Err(e);
    }

    if !quiet {
        println!("Signature: OK");
        println!("Trusted comment: {}", signature.trusted_comment);
        println!("Public key: {pk_source}");
        println!("Fingerprint: {}", public_key.fingerprint());
        // Anyone can copy another key's ID into a v1 signature and a public key of their own, and it still verifies.
        if signature.format() == SignatureFormat::V1 {
            eprintln!("note: format v1 does not sign the key ID, so only the fingerprint above identifies the signer");
        }
    }

    Ok(())
}
