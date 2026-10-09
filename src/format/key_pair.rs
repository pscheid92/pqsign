use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use super::file::{self, Access, Staged};
use super::kdf::Kdf;
use super::{public_key, secret_key};
use crate::domain::KeyPair;
use crate::errors::Error;

/// Writes a new key pair so that a failure never destroys an existing secret key.
///
/// Both files are encrypted, written and synced before either destination is touched. The public key is
/// renamed into place first and the secret key last: if the final rename fails, the old secret key survives.
/// Without `overwrite`, existing files are never replaced, and a public key written by this call is removed
/// again when the secret key cannot be placed.
pub fn write_key_pair(
    secret_path: &Path,
    public_path: &Path,
    keypair: &KeyPair,
    password: Zeroizing<String>,
    overwrite: bool,
    kdf: &Kdf,
) -> Result<(), Error> {
    let secret_data = secret_key::encode(&keypair.secret_key, &password, kdf)?;
    let public_text = public_key::encode_text(&keypair.public_key)?;

    let secret = Staged::new(secret_path, &secret_data, Access::Private)?;
    let public = Staged::new(public_path, public_text.as_bytes(), Access::Public)?;

    let public_dest = public.commit(overwrite)?;
    let secret_dest = match secret.commit(overwrite) {
        Ok(dest) => dest,
        Err(err) => {
            if !overwrite {
                let _ = fs::remove_file(&public_dest);
            }
            return Err(err);
        }
    };

    file::sync_parent_dir(&public_dest);
    file::sync_parent_dir(&secret_dest);
    Ok(())
}
