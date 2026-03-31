use std::path::{Path, PathBuf};

use super::util::resolve_signature_path;
use crate::errors::Error;
use crate::format;

pub fn run(file: PathBuf) -> Result<(), Error> {
    match format::inspect_file(&file) {
        Ok(info) => {
            println!("{info}");
            Ok(())
        }
        Err(Error::InvalidFormat(_)) if !has_pqsign_extension(&file) => {
            let sig_path = resolve_signature_path(None, &file)?;
            let info = format::inspect_file(&sig_path)?;
            eprintln!("(inspecting {})", sig_path.display());
            println!("{info}");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn has_pqsign_extension(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()), Some("key" | "pub" | "pqsig"))
}
