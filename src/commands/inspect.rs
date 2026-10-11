use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::util::resolve_signature_path;
use crate::errors::Error;
use crate::format;
use crate::terminal::SafePath;

pub fn run(file: PathBuf) -> Result<(), Error> {
    match format::inspect_file(&file) {
        Ok(info) => {
            println!("{info}");
            Ok(())
        }
        Err(Error::InvalidFormat(_)) if !has_pqsign_extension(&file) => {
            let sig_path = resolve_signature_path(None, &file)?;
            match format::inspect_file(&sig_path) {
                Ok(info) => {
                    eprintln!("(inspecting {})", SafePath(&sig_path));
                    println!("{info}");
                    Ok(())
                }
                // Report both, instead of only the missing signature, which hides that the file itself was rejected.
                Err(Error::IoPath { source, .. }) if source.kind() == ErrorKind::NotFound => {
                    let msg = format!("{} is not a pqsign file, and {} does not exist", SafePath(&file), SafePath(&sig_path));
                    let err = Error::InvalidFormat(msg);
                    Err(err)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn has_pqsign_extension(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()), Some("key" | "pub" | "pqsig"))
}
