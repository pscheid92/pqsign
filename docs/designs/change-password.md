# Change-password command: design

* **Author:** Patrick Scheid
* **Date:** 2026-11-19
* **Status:** Draft
* **Brief:** [change-password-brief.md](change-password-brief.md)

## Summary

`pqsign change-password` re-encrypts an existing secret key file under a new password and pqsign's default Argon2id parameters (256 MiB, 3 passes). It keeps the file's header and the decrypted payload bytes, so a format v1 file stays format v1, a format v2 file stays format v2, and the key ID, fingerprint and `.pub` file never change. The new file is read back in memory with the new password before it atomically replaces the old one.

This document turns the six decisions of the brief into code, error messages, documentation and tests. It settles the five open points the brief left for the draft:

1. the library API, and how it shares parsing with `read_with`: Design, sections 1 to 3
2. the prompts and error wording: section 3 (`check_rewritten`, `check_unchanged`) and section 4
3. the documentation changes: Documentation, and the help text in section 5
4. the test plan: Tests
5. the release: Release

## Background

A secret key file, in both format versions:

| Offset | Length | Field | Changed by `change-password` |
|---|---|---|---|
| 0 | 14 | Header: magic `PQSN`, version, file type, key ID | no, written back unchanged |
| 14 | 17 | KDF block: algorithm byte, memory, iterations | yes, the `kdf` argument; the CLI passes `Kdf::argon2id()` |
| 31 | 16 | Argon2id salt | yes, fresh |
| 47 | 24 | XChaCha20 nonce | yes, fresh |
| 71 | 4,088 (format v1) or 80 (format v2) | Encrypted payload and tag | yes, same plaintext under a new key |

The AEAD doesn't bind the header, so the original header followed by a new KDF block, salt, nonce and ciphertext is a valid file. The header is still checked when the key is loaded, by the key-ID check of its format version. The payload length depends only on the version, so the rewritten file has the same length as the old one: 4,159 bytes for format v1, 151 for format v2.

`seal` writes the parsed header back with `FileHeader::write_to`, which writes all four fields as they were read, so the 14 bytes come out identical. `check_rewritten` compares them to make sure.

What exists today, in `src/format/secret_key.rs`:

- `read_with(path, password_fn)` reads the header, KDF block, salt and nonce, checks the ciphertext length for the version, calls `password_fn`, decrypts with `decrypt_payload`, and decodes with the frozen `decode_v1` or with `decode_v2`.
- `decrypt_payload` returns the plaintext in a `Zeroizing<Vec<u8>>`. Its comment already names re-encryption as a use.
- `encode_v2(seeds, password, kdf)` builds the format v2 payload, then writes header, KDF block, salt, nonce and ciphertext. Only that last part is needed again here.
- `file::write` writes a temporary file in the same directory with mode 0600 on Unix, fsyncs it, renames it over the destination (following a symlink to its target) and syncs the directory, on Unix and best effort.

## Design

### 1. Library: split `read_with` into parse, decrypt and decode

`read_with` does two things that `change_password` needs separately, and twice (once for the old file, once to read back the new bytes): parsing everything that needs no password, and opening the payload with one. They become three private functions, `parse`, `decrypt` and `decode`, and `read_with` becomes their composition. Its behaviour, its order of checks and its error messages do not change.

```rust
/// Everything in a secret key file that can be checked without the password.
struct Parsed<'a> {
    header: FileHeader,
    kdf: Kdf,
    salt: [u8; ARGON2_SALT_LEN],
    nonce: [u8; XCHACHA20_NONCE_LEN],
    ciphertext: &'a [u8],
}

/// Checks the header, the KDF parameters and the ciphertext length for the format version.
fn parse(data: &[u8]) -> Result<Parsed<'_>, Error>;

/// Decrypts the payload of a parsed file into a buffer that is wiped on drop.
fn decrypt(parsed: &Parsed<'_>, password: &Zeroizing<String>) -> Result<Zeroizing<Vec<u8>>, Error>;

/// Decodes a decrypted payload by format version, which runs that version's key-ID check.
fn decode(plaintext: &[u8], header: &FileHeader) -> Result<SecretKey, Error>;

pub fn read_with(path: &Path, password_fn: impl FnOnce(&Kdf) -> Result<Zeroizing<String>, Error>) -> Result<SecretKey, Error> {
    let data = file::read(path)?;
    let parsed = parse(&data)?;
    let password = password_fn(&parsed.kdf)?;
    let plaintext = decrypt(&parsed, &password)?;
    decode(&plaintext, &parsed.header)
}
```

`decode` dispatches on the header version to `decode_v1` or `decode_v2` exactly as `read_with` did before. It returns the `SecretKey` straight to its caller. An earlier version of this design returned a struct holding both the plaintext and the key from one `open` function; on Windows, whose main thread has a 1 MiB stack, the extra moves of the large ML-DSA-65 key in a debug build overflowed the stack in `sign`, which already came close to that limit before this change. With `decrypt` and `decode` apart, `read_with` keeps the stack use it had. `decode_v1` and `deserialize_payload` are not touched.

### 2. Library: one writer for the sealed part

The sealed part of a secret key file is everything after the header: the KDF block, salt, nonce and ciphertext. `Parsed` holds a whole file, header included. The sealed part is written in one place, used by both `encode_v2` and `change_password`:

```rust
/// Writes `header`, then the KDF block, a fresh salt and nonce, and `plaintext` encrypted under `password`.
/// The KDF parameters are checked first, so pqsign never writes a key it would refuse to read.
fn seal(header: &FileHeader, plaintext: &[u8], password: &Zeroizing<String>, kdf: &Kdf) -> Result<Vec<u8>, Error>;
```

The public entry points check the parameters before any other work: `encode_v2` keeps `kdf.check()?` as its first line, before it derives the key ID, and `change_password` makes it its first line, before it reads the file or asks for a password. The check in `seal` stays as a safety net for later callers.

`encode_v2` keeps building its payload with the exact capacity, derives the key ID, and ends with `seal(&FileHeader::new(FileType::SecretKey, key_id), &payload, password, kdf)`. Its output stays the same. `encrypt_payload` moves into `seal`.

### 3. Library: `change_password`

```rust
/// What `change_password` rewrote, for the caller's status line.
pub struct PasswordChanged {
    /// The secret key format version, from the header, which is kept.
    pub version: u8,
    pub key_id: KeyId,
    pub fingerprint: Fingerprint,
    /// The Argon2id parameters the file was written with.
    pub kdf: Kdf,
}

/// Re-encrypts a secret key file under a new password and `kdf`, keeping its header and payload bytes, so the
/// key, its format version, key ID and fingerprint stay the same. `current` is called after every check that
/// needs no password, and `new` only after the current password has opened the file. The new file is read
/// back with the new password before it atomically replaces the old one.
pub fn change_password(
    path: &Path,
    current: impl FnOnce(&Kdf) -> Result<Zeroizing<String>, Error>,
    new: impl FnOnce() -> Result<Zeroizing<String>, Error>,
    kdf: &Kdf,
) -> Result<PasswordChanged, Error> {
    kdf.check()?;
    let data = file::read(path)?;
    let parsed = parse(&data)?;
    let plaintext = decrypt(&parsed, &current(&parsed.kdf)?)?;
    let (key_id, fingerprint) = {
        let secret_key = decode(&plaintext, &parsed.header)?;
        (secret_key.key_id(), secret_key.fingerprint())
    };

    let new_password = new()?;
    let rewritten = seal(&parsed.header, &plaintext, &new_password, kdf)?;
    check_rewritten(&rewritten, &data, &new_password, &plaintext, kdf)?;
    check_unchanged(path, &data)?;

    file::write(path, &rewritten, Access::Private)?;
    Ok(PasswordChanged {
        version: parsed.header.version,
        key_id,
        fingerprint,
        kdf: *kdf,
    })
}
```

`change_password` is re-exported as `format::change_secret_key_password`, together with `PasswordChanged`, next to `read_secret_key_with` and `write_secret_key`, so callers outside the crate can name the return type. The brief called it `format::secret_key::change_password`; that path can't be public because `mod secret_key` is private, so it is re-exported like the other secret key functions.

The `kdf` argument is `Kdf::argon2id()` from the CLI. Tests pass small parameters, as they do for `generate`.

A successful run costs three Argon2id derivations in sequence: one with the file's parameters to open it, and two with `kdf`, to seal and to read back. At the defaults that is about 1.2 s. Peak memory is one derivation's, 256 MiB, because they run one after another.

```rust
/// Reads the re-encrypted bytes back before they replace the file. Any failure here is a bug in `seal` or
/// below, never a user error, so every failure becomes the same error.
fn check_rewritten(rewritten: &[u8], original: &[u8], password: &Zeroizing<String>, plaintext: &[u8], kdf: &Kdf) -> Result<(), Error>;
```

It requires, in order:

1. the same length as the original file;
2. the same first 14 bytes, the header;
3. that `parse` accepts the bytes and reads back exactly `kdf`;
4. that `decrypt_payload` with the new password succeeds;
5. that the decrypted plaintext equals `plaintext`, the original's.

It doesn't decode the plaintext again. With the same header and the same plaintext, the decode is deterministic, so comparing the plaintext is enough, and it avoids another copy of a format v1 key inside fips204, which pqsign can't wipe.

Every failure, including a `WrongPassword` from decryption or a format error from `parse`, becomes one `Error::Crypto`:

```text
the re-encrypted secret key did not read back with the new password; the secret key file was left unchanged; please report this as a pqsign bug
```

`check_unchanged` reads the file again, right before it is replaced, and requires it to equal `data` byte for byte. Between the first read and the write lie a prompt with no time limit and up to three Argon2id runs. If `generate --overwrite -s KEY` ran in that window, writing back the old key would leave the `.key` and the `.pub` from different keys, and nothing would report it. A difference stops the command with a new error, and nothing is written:

```rust
#[error("{} changed while its password was being changed; nothing was written; run change-password again", SafePath(.0))]
KeyFileChanged(std::path::PathBuf),
```

This is not a lock. A change in the few milliseconds `file::write` takes is still lost; `flock` would not close that gap either, because the rename replaces the inode. It closes the realistic case, a second command run while the first waits at a prompt.

Passing the inner error up from `check_rewritten` instead would print `wrong password (decryption failed)` right after the user typed the correct current password, and would not say that the file is intact.

`Kdf` gains a `Display` impl in `src/format/kdf.rs`: `Argon2id, {memory}, {n} passes`, with `1 pass` in the singular and the memory from `kdf::exact_size`, for example `Argon2id, 256 MiB, 3 passes`. It lives there because `exact_size` is `pub(super)`, so the command can't format the memory itself. "Passes" is the word the brief and `ARCHITECTURE.md` use. `inspect` keeps its own output.

### 4. Password input

`PasswordSource` gets the prompt text as a parameter. The existing methods keep their prompts.

```rust
impl PasswordSource {
    pub fn read_existing(self) -> Result<Zeroizing<String>, Error> { self.read_existing_as("Password: ") }
    pub fn read_new(self) -> Result<Zeroizing<String>, Error> { self.read_new_as("Password: ", "Confirm password: ") }

    pub fn read_existing_as(self, prompt: &str) -> Result<Zeroizing<String>, Error>;
    pub fn read_new_as(self, prompt: &str, confirm: &str) -> Result<Zeroizing<String>, Error>;
}
```

The bodies change as little as possible:

- `read_existing_as` is today's `read_existing`, with `prompt` passed to `prompt_password` instead of `"Password: "`.
- `read_new_as` is today's `read_new`: for `Prompt` it calls `prompt_new_password(prompt, confirm)`, for every other source `read_existing_as(prompt)`, and in both cases `require_max_len` afterwards.
- `prompt_new_password(prompt, confirm)` takes the two strings it hard-codes today.
- `read_existing` and `read_new` become the one-line wrappers above, so `generate` and `sign` keep their prompts.

`change-password` prompts with `Current password: `, then `New password: ` and `Confirm new password: `.

The errors for empty, too long or mismatched passwords keep their generic wording, such as `password cannot be empty`. They can't be misread: only one password is in play at each step, the current one until the file is open and the new one after it, and the prompt just shown names which.

`Error::PasswordPrompt` names the options to use instead of a terminal. That message is wrong for the new password, which only `--new-password-file` can give. `PasswordPrompt` is built in one place, `prompt_password` in `password.rs`, which `generate` also reaches through `read_new`, so changing it there would send `generate` users to an option `generate` doesn't have. Instead, a new variant carries the other message, and `change-password` maps to it in its `new` closure (section 6). `password.rs`, `generate` and `sign` don't change.

```rust
#[error("cannot prompt for a new password: {source}; use --new-password-file when no terminal is available")]
NewPasswordPrompt { source: std::io::Error },
```

| Prompt fails while asking for | Error | Message |
|---|---|---|
| the current password, or any password in `generate` and `sign` | `PasswordPrompt` | `cannot prompt for a password: {source}; use --password-stdin or --password-file when no terminal is available` (unchanged) |
| the new password in `change-password` | `NewPasswordPrompt` | `cannot prompt for a new password: {source}; use --new-password-file when no terminal is available` |

A wrong current password is the existing `Error::WrongPassword`, `wrong password (decryption failed)`, exit status 2, the same as `sign`. The command is about the current password at that point, so no new wording is needed.

### 5. Command line

```rust
/// Change the password of a secret key
#[command(after_help = CHANGE_PASSWORD_HELP)]
ChangePassword {
    #[arg(short = 's', long = "secret-key", help = "Secret key file path [default: ~/.pqsign/default.key]")]
    secret_key: Option<PathBuf>,

    #[command(flatten)]
    password: PasswordArgs,

    /// Read the new password from the first line of a file
    #[arg(long, value_name = "PATH")]
    new_password_file: Option<PathBuf>,
},
```

`PasswordArgs` describes its options as giving "the password". For `change-password` that is the current password, which the help text says, since a doc comment on a flattened field does not show in `--help`. The constant sits next to `EXIT_STATUS_HELP` in `main.rs`:

```rust
const CHANGE_PASSWORD_HELP: &str = "\
The key, its key ID, its fingerprint and its .pub file stay the same, so existing signatures still verify and \
nobody needs the public key again. The file is replaced, not edited in place, and written with pqsign's \
default Argon2id parameters (256 MiB, 3 passes).

--password-stdin and --password-file give the current password; --new-password-file gives the new one.

A new password does not protect copies of the secret key file made before the change: backups, synced copies, \
other hard links to the file. If the secret key file and its password were exposed together, generate a new key.";
```

The match arm in `Cli::run`:

```rust
Command::ChangePassword {
    secret_key,
    password,
    new_password_file,
} => change_password::run(change_password::Options {
    secret_key,
    password: password.into(),
    new_password: new_password_file.map_or(PasswordSource::Prompt, PasswordSource::File),
    kdf: Kdf::argon2id(),
}),
```

### 6. The command

`src/commands/change_password.rs`:

```rust
pub struct Options {
    pub secret_key: Option<PathBuf>,
    pub password: PasswordSource,
    /// The command line passes only `Prompt` or `File`, so standard input never carries the new password.
    pub new_password: PasswordSource,
    /// The command line always passes [`Kdf::argon2id`]; tests pass small parameters.
    pub kdf: Kdf,
}

pub fn run(opts: Options) -> Result<(), Error> {
    let Options { secret_key, password, new_password, kdf } = opts;
    let secret_key_path = resolve_key_path(secret_key, "default.key")?;
    let old_mode = mode_if_accessible_by_others(&secret_key_path);

    warn_if_directory_writable_by_others(&secret_key_path, "secret key");
    for source in [&password, &new_password] {
        if let PasswordSource::File(path) = source {
            warn_if_accessible_by_others(path, "password file");
        }
    }

    let changed = format::change_secret_key_password(
        &secret_key_path,
        |_kdf| password.read_existing_as("Current password: "),
        || {
            new_password.read_new_as("New password: ", "Confirm new password: ").map_err(|err| match err {
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
```

Nothing goes to stdout. There is no warning about the key file's own permissions, unlike `sign`: the rewritten file has mode 0600 on Unix whatever it had before. Instead, after a successful change, a note says when the old file was accessible by other users, because anyone who could read it may have kept a copy under the old password. `mode_if_accessible_by_others` is a new helper in `commands/util.rs`, returning the mode when it has `0o077` bits set, on Unix only; `warn_if_accessible_by_others` is rebuilt on it. On Windows, `Access` is ignored and the new file inherits the ACL of its directory, so a key whose permissions were narrowed by hand gets the directory's permissions back.

`new_password` is `PasswordSource::File` when `--new-password-file` is given, else `PasswordSource::Prompt`. Standard input never carries the new password.

## Behaviour at the edges

| Situation | Result |
|---|---|
| The key file is missing or unreadable | The I/O error with its path, as for `sign`. No password is asked for. |
| The file is a public key or signature, or is truncated, padded or relabelled | The existing `read_with` errors. No password is asked for. |
| Empty current password | `password cannot be empty`, as for `sign`. No new password is asked for. The file is unchanged. |
| Wrong current password | `wrong password (decryption failed)`. No new password is asked for. The file is unchanged. |
| A format v2 file whose key doesn't match its key ID | The existing `decode_v2` error. The file is unchanged. |
| New password empty, too long, or the confirmation differs | The existing `generate` errors. The file is unchanged. |
| The new password equals the current one | Allowed. Fresh salt and nonce, pqsign's default Argon2id parameters. |
| `-s` is a symlink | The target is rewritten; the symlink stays. The directory warning checks the symlink's directory, not the target's, as it does for `sign`. |
| The old file was accessible by other users (Unix) | After the change, a `note:` with its old mode says that copies made before now keep the old password. The new file has mode 0600. |
| The key file has other hard links | Only this path gets the new file. The other links keep the old file under the old password, as the help text warns. |
| Another process changes the file while the command waits at a prompt or runs Argon2id | `KeyFileChanged`. Nothing is written; the other process's file stays. |
| Another process changes the file during the final `file::write`, a few milliseconds | Its change is lost. Not guarded against; this would need a lock that a rename can't keep. |
| The re-encrypted bytes don't read back (a pqsign bug) | The `check_rewritten` bug-report error. Nothing is written; the file is unchanged. |
| The write or rename fails | The old file is intact; the temporary file is removed. |
| The key's directory is not writable | The write fails after both prompts, with the I/O error for the key path. The file is unchanged. |
| The key file has another owner, group, POSIX ACLs or extended attributes | Not kept: the rename puts a new file in place, owned by whoever runs the command, with mode 0600 on Unix. |
| Run with `sudo` on a user's key | The key ends up owned by root with mode 0600, unreadable for the user. |
| The process is killed during the write | The old file is intact. A `.<name>.<random>.tmp` file with mode 0600 may stay behind, holding the key under the new password. |

## Security considerations

- **Earlier copies keep the old password.** Backups, synced copies, other hard links and files an attacker already has are not reached. The help text, README and `docs/cryptography.md` say so; a key whose file and password were exposed together needs `generate`.
- **The file is replaced, not edited.** Owner, group, ACLs and extended attributes are not kept; mode 0600 is set on Unix. On Windows the new file inherits the directory's ACL, so permissions narrowed by hand are lost. A symlink is followed to its target, and the directory warning checks the symlink's directory, as for `sign`.
- **Secrets in memory.** The decrypted payload is held in `Zeroizing<Vec<u8>>` from `decrypt_payload` until the new file is written, and the read-back plaintext in another one. Both passwords are `Zeroizing<String>`. A format v1 key is decoded once, so fips204 gets one copy of the expanded key that pqsign can't wipe, as for `sign`; `check_rewritten` doesn't decode again, so there is no second one.
- **No partial writes.** The new file is read back before it replaces the old one, and replaced by rename. A killed process can leave a `.tmp` file with mode 0600 that holds the key under the new password.
- **Concurrent changes.** `check_unchanged` stops a write over a file that changed while the command waited at a prompt. A change in the last few milliseconds before the rename is still lost; a rename can't hold a lock.
- **No new parsing surface.** The command reads files with the same checks as `sign`, in the same order, and asks for no password before they pass.

## Alternatives considered

The product decisions, such as format v1 handling, the Argon2id parameters, the command line and the read-back, are the brief's; its "Alternatives Weighed" lists what was rejected there. These are the draft's own choices:

- **Split `read_with` into `parse`, `decrypt` and `decode`,** instead of a second reader for `change_password`. One copy of the checks that run before the password, so `change-password` can't drift from `sign` in what it accepts. The cost is a refactor of `read_with`, done first with the existing tests unchanged.
- **Separate steps rather than one `open_bytes(data, password_fn)` returning header, KDF, plaintext and key.** The read-back would then need a clone of the new password to pass through `password_fn`, one more copy of a secret, and the key would travel inside a larger return value, which costs stack (see section 1).
- **One `seal` for both writers,** instead of a re-encryption function next to `encode_v2`. One place writes the layout after the header.
- **A new `NewPasswordPrompt` error variant,** instead of a hint field set by the caller or a hint parameter in `password.rs`. `password.rs` stays free of CLI option names, and `generate` and `sign` don't change.
- **Prompt text as a parameter (`read_*_as`),** instead of changing the existing methods. `generate` and `sign` keep their calls; the two new methods are the existing bodies with one string each made a parameter.
- **`check_rewritten` compares the plaintext only,** not the fingerprint as well. With the same header and plaintext, the decode is deterministic, and a second decode would give fips204 another unwipeable copy of a format v1 key.
- **`check_unchanged` in `change_password`,** instead of a compare-and-replace inside `file.rs`. It closes the window of a waiting prompt with five lines; a `file.rs` variant would only narrow the remaining few milliseconds.

## Scope

As in the brief: no format v1 to v2 conversion, no Argon2id options, no removal of encryption, no change to the key ID or the `.pub` file, no revocation of earlier copies, no backup file, and no authenticated header. See the brief's Goals vs. Non-Goals.

## Documentation

`change-password` writes format v1 files again, by re-encrypting their payload, and it is the first command with two passwords. Several statements become false with it; each is listed here with its new content.

The invariant, wherever it is stated, becomes: **pqsign encodes only secret key format v2; `change-password` re-encrypts a format v1 payload unchanged, and no format v1 encoder exists.**

**README.md**

- A new `### Change a key's password` section after "Sign a file": the command, that the key, key ID, fingerprint and `.pub` file stay the same, that the file is replaced rather than edited in place (so owner, ACLs and extended attributes are not kept), and the limit on copies made before the change.
- Line 77, "`generate` and `sign` prompt for the secret key password": add `change-password`, which prompts for the current and the new password.
- "Non-interactive use", line 85 onwards: a `change-password` example with `--password-file` and `--new-password-file`, and the rule that standard input only carries the current password.

**ARCHITECTURE.md**

- Lines 31–33, `src/main.rs`: add `change-password` to the subcommands; "the other four" becomes "the other five".
- Lines 64–66, the `format` module: secret keys are encoded in format v2, and `change-password` re-encrypts format v1 files without decoding them into a new layout. Name `parse`, `decrypt`, `decode`, `seal` and `change_password`.
- Lines 106–108, "Ask for the password last": every check that needs no password runs before the first prompt, and `change-password` asks for the new password only after the current one has opened the file.
- Line 113, file permissions: secret keys are exactly `0600`, also when `change-password` replaces one.
- Lines 119–120, "Every secret key format stays readable": the invariant wording above.
- Lines 129–137, side effects: files written include a secret key rewritten by `change-password`; the terminal prompts include the current and new password; a password file can be `--new-password-file`; `change-password` runs Argon2id three times, once with the file's parameters and twice with the defaults.

**docs/cryptography.md**

- Line 153, "still reads and no longer writes": format v1 is still read, never encoded, and `change-password` re-encrypts its payload unchanged, so a format v1 key keeps its format and its fingerprint.
- Under the secret key format, a paragraph saying that `change-password` keeps the header and the payload bytes and replaces the KDF block, salt, nonce and ciphertext, and that the new bytes are read back before they replace the file.
- Lines 175–176, `0600` and atomic writes: they apply to `change-password` too.
- The memory-safety list: the plaintext held for re-encryption is in a zeroizing buffer, wrapped as soon as `crypto::decrypt` returns it. As for `sign`, loading a format v1 key hands fips204 a copy of the expanded key that pqsign can't wipe; `change-password` does that once, since the read-back compares plaintext without decoding.
- The warnings list: `change-password` warns about password files and the key's directory, as `sign` and `generate` do.

**Code comments**, changed in implementation step 2 together with the code:

- `src/format/secret_key.rs:26`, "Nothing writes format v1 any more": nothing encodes format v1; `change_password` re-encrypts existing format v1 payloads.
- `src/format/secret_key.rs:155`, "which pqsign no longer writes": which pqsign no longer encodes.
- `src/password.rs:1`, "for key generation and signing": add changing a password. Lines 20–26, the `PasswordSource` docs: "the secret key password" also covers the new password.

**Help text:** `CHANGE_PASSWORD_HELP` in `src/main.rs`, written out in section 5.

**Release notes** for 0.5.0, written at release time.

## Tests

Every row of the edge table and every test item of the brief has a test below. Where an existing test already does the same thing for `generate` or `read_with`, it is named, and the new test copies its approach.

Library, in `src/format/tests.rs`, with small Argon2id parameters:

- A format v2 key written with `{64 KiB, 1}` is changed with `{128 KiB, 2}`, as `test_secret_key_records_its_kdf_parameters` does. Afterwards the file has the same length (151 bytes) and the same first 14 bytes, bytes 14 to 31 hold the new parameters, it opens with the new password, and it gives the same key ID and fingerprint. The returned `PasswordChanged` holds the key's version, key ID and fingerprint.
- The old password fails afterwards with `WrongPassword`.
- Salt and nonce differ from before, also when the new password equals the current one.
- Nothing is asked for on a file that fails the checks needing no password: relabelled, truncated and padded files, and a public key file, with `current = |_| panic!()` and `new = || panic!()`, as `test_secret_key_relabelled_version_detected_before_password` and `test_secret_key_wrong_length_detected_before_password` do. The errors are the same as `read_with`'s.
- A wrong current password, and `current` returning an error: `WrongPassword` or that error, `new = || panic!()` is never reached, and the file is byte for byte unchanged.
- `new` returning an error: the file is byte for byte unchanged.
- Invalid `kdf` parameters, for example an iteration count over the limit: the `Kdf::check` error, `current = |_| panic!()` is never reached, and the file is byte for byte unchanged.
- A `new` closure that rewrites the key file before returning the new password, standing in for a concurrent `generate --overwrite`: `change_password` fails with `KeyFileChanged`, and the file holds the bytes the closure wrote.
- `check_rewritten`, in a `#[cfg(test)]` module inside `secret_key.rs`, since it is private: correct bytes pass; bytes with one ciphertext byte flipped, a wrong password, a changed header byte, a different length, or a different KDF block each give the bug-report error, never `WrongPassword` or `InvalidFormat`.
- `read_with` still behaves as before the split: the existing tests pass unchanged.
- `encode_v2` still writes the same layout: the existing format v2 layout test passes unchanged.

Fixtures, in `tests/fixtures.rs`, on copies in a temporary directory. `tests/fixtures.rs` is its own test crate, so it defines its own small `Kdf`, like `TEST_KDF` in `tests/cli.rs`; reading `v1-random-id.key` still costs one derivation at 256 MiB, its own parameters.

- `v1.key`, `v1-random-id.key` and `v2.key` each keep their version, length (4,159, 4,159 and 151 bytes), header, key ID and fingerprint after the change. Each opens with the new password, fails with `fixture-password` with `WrongPassword`, and signs a file that verifies against its committed `.pub`.

Command, in `tests/integration.rs`. `run` returns `()` and prints only to stderr, so these tests check the result and the files:

- `Options` with `PasswordSource::Given` for both passwords and small parameters: `run` returns `Ok(())`, the key then loads with the new password and not with the old one, and its key ID and fingerprint are unchanged.
- An empty new password gives `PasswordEmpty`, and one of `MAX_PASSWORD_LEN + 1` bytes gives `PasswordTooLong`. In both cases the file is byte for byte unchanged.
- No temporary files are left next to the key afterwards, as in `test_generate_leaves_no_temp_files`.
- Unix only:
  - `-s` naming a symlink rewrites its target, and the symlink stays a symlink, as in `test_generate_overwrite_writes_through_symlink`.
  - A second hard link to the key file still opens with the old password afterwards, and the changed path with the new one.
  - With the key's directory made read-only (mode 0500), the write fails, the file is byte for byte unchanged, and no temporary file is left. Like `test_generate_overwrite_keeps_old_key_when_public_key_cannot_be_replaced`, it forces the failure through the file system. Skipped when running as root, which ignores the mode.

A new password whose confirmation differs can only be typed at a terminal, so no automated test reaches it through the command. `validate_new_password`'s unit tests in `password.rs` cover the check itself.

The status values are checked in the library tests above, on the returned `PasswordChanged`. Output on stderr is checked in the CLI tests below, which run the binary.

CLI, in `tests/cli.rs`. `change-password` always writes with the default Argon2id parameters, 256 MiB, so a successful run costs two Argon2id runs at that size, about 0.8 s, and a `sign` afterwards a third. Only the round-trip test pays all of that and checks the result in full; the other CLI tests are kept because only the binary shows what they check (stderr, exit status, clap), and their cost is accepted. Keys come from `generate_key` with `TEST_KDF`, so reading the current password stays cheap.

- The round trip: `change-password -s KEY --password-file OLD --new-password-file NEW`, then `sign` with `NEW` and `verify` against the unchanged `.pub`. The rewritten file has mode 0600 (Unix), and `inspect` prints `Memory:      256 MiB` and `Ops:         3`, with the padding, as `test_cli_generate` matches them.
- `--password-stdin` for the current password together with `--new-password-file`.
- `--password-stdin` and `--password-file` together are refused by clap, as for `sign`.
- `change-password --help` contains `give the current password`.
- Under `#[cfg(unix)]`: a key file with mode 0644 gets the `note: … was accessible by other users (mode 0644)` line after the change, and mode 0600 afterwards; a key file with mode 0600 gets no note.
- An empty `--new-password-file` fails with `password cannot be empty`, and the file is unchanged.
- Without a terminal and without `--new-password-file`, under `#[cfg(unix)]` and with the `/dev/tty` skip guard of `test_cli_sign_without_terminal_requires_password_option`: the key comes from `generate_key` (`test-pw`, `TEST_KDF`), and `--password-file` holds `test-pw`, so the current password is read without a prompt and the new-password prompt is the one that fails. The command fails, stderr contains `--new-password-file`, and the file is byte for byte unchanged. Like the `sign` test, it only runs where no terminal is available, as in CI; in an interactive `cargo test` it skips itself instead of waiting at the prompt.
- Under `#[cfg(unix)]`, like the existing permission-warning tests: with mode 0640 on both `--password-file` and `--new-password-file`, stderr has `warning: password file {path} is accessible by other users (mode 0640)` once for each file.

## Files

| File | Change |
|---|---|
| `src/format/secret_key.rs` | `Parsed`, `parse`, `decrypt`, `decode`, `seal`, `change_password`, `check_rewritten`, `check_unchanged`, `PasswordChanged`; `read_with` and `encode_v2` rebuilt on them; two comments about format v1; the `check_rewritten` unit tests |
| `src/format/kdf.rs` | `impl fmt::Display for Kdf` |
| `src/format/mod.rs` | re-export `change_password as change_secret_key_password` and `PasswordChanged` |
| `src/format/tests.rs` | library tests |
| `src/errors.rs` | `NewPasswordPrompt`, `KeyFileChanged` |
| `src/password.rs` | `read_existing_as`, `read_new_as`; module and `PasswordSource` docs |
| `src/commands/change_password.rs` | new: `Options`, `run` |
| `src/commands/util.rs` | `mode_if_accessible_by_others`; `warn_if_accessible_by_others` rebuilt on it |
| `src/commands/mod.rs` | `pub mod change_password;` |
| `src/main.rs` | `change_password` in the `use pqsign::commands::{…}` import, `CHANGE_PASSWORD_HELP`, `Command::ChangePassword`, its match arm |
| `tests/fixtures.rs`, `tests/integration.rs`, `tests/cli.rs` | fixture, command and CLI tests |
| `README.md`, `ARCHITECTURE.md`, `docs/cryptography.md` | as listed under Documentation |
| `Cargo.toml`, `Cargo.lock` | version 0.5.0, in the release pull request, not in the feature |

## Implementation order

1. Split `read_with` into `parse` and the decrypt-and-decode step, and move the sealed part of `encode_v2` into `seal`. No behaviour change; the existing tests must pass unchanged.
2. Split that step into `decrypt` and `decode`, so `change_password` keeps the plaintext. Add `change_password`, `check_rewritten`, `check_unchanged`, `PasswordChanged`, `Display for Kdf`, `Error::KeyFileChanged`, and their library and fixture tests. Update the two `secret_key.rs` comments that say format v1 is never written.
3. Add the prompt parameters to `PasswordSource` and the `Error::NewPasswordPrompt` variant.
4. Add the command and the CLI, with the command and CLI tests.
5. Documentation, and the manual cross-check with pqsign 0.1.1 and 0.3.1 described under Release.

Each step passes `cargo clippy --locked --all-targets -- -D warnings` and the full test suite on its own, as CI requires.

## Release

0.5.0: a new command, no format change, no change to existing commands. Files written by `change-password` are readable by every pqsign that reads their format version: format v1 files by 0.1.0 and later, format v2 files by 0.4.0 and later.

The format v1 claim rests on `change-password` writing exactly the Argon2id parameters pqsign 0.1 always used, 256 MiB and 3 passes, into an unchanged layout. Nothing in the tree tests it, so the implementation checks it once by hand and records the result in the pull request: change the password of a copy of `v1-random-id.key`, then sign with it using the published pqsign 0.1.1 and 0.3.1, and verify both signatures with the current build.

The release notes also list the library changes: `format::change_secret_key_password` and `PasswordChanged`, `PasswordSource::read_existing_as` and `read_new_as`, and the `Error` variants `NewPasswordPrompt` and `KeyFileChanged`. The library is declared unstable in `lib.rs`, so these need no compatibility promise.

## Open questions

None.
