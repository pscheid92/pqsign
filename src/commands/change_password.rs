use std::path::PathBuf;

use super::util::{mode_if_accessible_by_others, resolve_secret_key_path, warn_about_key_setup};
use crate::errors::Error;
use crate::format::{self, Kdf};
use crate::password::PasswordSource;
use crate::terminal::SafePath;

pub struct Options {
    pub secret_key: Option<PathBuf>,
    /// The current password.
    pub password: PasswordSource,
    /// The command line passes only `Prompt` or `File`, so standard input never carries the new password.
    pub new_password: PasswordSource,
    /// The command line always passes [`Kdf::argon2id`]; tests pass small parameters.
    pub kdf: Kdf,
}

pub fn run(opts: Options) -> Result<(), Error> {
    let Options {
        secret_key,
        password,
        new_password,
        kdf,
    } = opts;
    let secret_key_path = resolve_secret_key_path(secret_key)?;
    // The rewritten file is private whatever the old one was, so instead of a warning, the old mode becomes a
    // note afterwards: anyone who could read the old file may have kept a copy under the old password.
    let old_mode = mode_if_accessible_by_others(&secret_key_path);

    warn_about_key_setup(&secret_key_path, &[&password, &new_password]);

    let changed = format::change_secret_key_password(
        &secret_key_path,
        |_kdf| password.read_existing_as("Current password: "),
        || {
            new_password
                .read_new_as("New password: ", "Confirm new password: ")
                .map_err(|err| match err {
                    Error::PasswordPrompt { source } => Error::NewPasswordPrompt { source },
                    other => other,
                })
        },
        &kdf,
    )?;

    eprintln!("Secret key:  {} (format v{})", SafePath(&secret_key_path), changed.version);
    eprintln!("Key ID:      {}", changed.key_id);
    eprintln!("Fingerprint: {}", changed.fingerprint);
    eprintln!("KDF:         {}", changed.kdf);
    if let Some(mode) = old_mode {
        let path = SafePath(&secret_key_path);
        eprintln!("note: {path} was accessible by other users (mode {mode:04o}); copies made before now keep the old password");
    }

    Ok(())
}
