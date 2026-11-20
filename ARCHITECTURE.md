# Architecture

How the pqsign code is organized, what each part is responsible for, and the rules that hold across them. For the
cryptographic design and the byte layout of each file, see [cryptography.md](docs/cryptography.md); this document
covers the code.

pqsign is one Cargo package with a binary (`src/main.rs`) and a library (`src/lib.rs`). The library exists only so
the binary, the tests and the benchmarks can share code. Every module in it is `#[doc(hidden)]`, and it is not a
stable API.

## Layers

```
src/main.rs        command line (clap), dispatch, exit codes
    │
src/commands/      one `run` per subcommand: resolve paths, pre-checks, print results
    │
    ├── src/format/    files: header, public/secret key and signature encoding, encryption, reads and writes
    │       │
    └───────┴── src/domain/   keys, fingerprints, signatures; signing and verifying

beside the layers: src/errors.rs (Error), src/password.rs (PasswordSource), src/terminal.rs (SafePath, SafeText)
```

Between the layers, calls go downwards only: `commands` calls `format` and `domain`, `format` calls `domain`, and
`domain` calls neither. `domain` does no file writes and no terminal output, and outside its tests it imports only
`errors` of the crate's own modules. The three modules beside the layers are not leaves: `errors` names `domain`'s
`KeyId` and `Fingerprint` in its messages and escapes paths with `terminal::SafePath`, so `errors` and `domain`
import each other. `password` is used by `main` and `commands` only, and `terminal` by `main`, `commands`,
`format` (trusted comments) and `errors`.

### `src/main.rs`

Defines the subcommands `generate`, `sign`, `change-password`, `verify`, `inspect`, `completions` and a hidden
`version`, converts the parsed arguments into the `Options` of each command (`inspect` takes just the path), and
turns the result into an exit code. `completions` and `version` are handled here; the other five call
`commands::<name>::run`.

`main` does all of this on a thread with an 8 MiB stack and waits for it. ML-DSA-65 in `fips204` keeps large values on
the stack, and an unoptimized `sign` does not fit in the 1 MiB a Windows main thread gets. The thread is named `main`,
and a panic on it is raised again on the real main thread, so output and exit codes are the same as without it. If
the thread can't be created, `main` runs the command on the real main thread instead.

### `src/commands/`

- `generate`: checks that neither key file exists (unless `--overwrite`), reads a new password, generates
  `SecretSeeds` and writes them with `format::write_key_pair`, which returns the public key it prints. The public
  key text goes to stdout.
- `sign`: validates the input file, the signature path and the trusted comment, then asks for the password, signs
  and writes the signature, to `<file>.pqsig` unless `-x` names another path. It refuses a signature path that is
  the file being signed or one of the key files, also through a symlink and, on Unix, a hard link.
- `change_password`: asks for the current password, then the new one, and calls
  `format::change_secret_key_password`, which re-encrypts the secret key file. It warns about password files and
  the key's directory, and notes afterwards when the old key file was accessible by other users.
- `verify`: reads the public key (from a file or `-P`) and the signature, then calls `Signature::verify`. `-q` only
  suppresses output; it never changes the result.
- `inspect`: prints what `format::inspect_file` finds. When `inspect_file` rejects the file as invalid, for
  example because it isn't a pqsign file, is corrupt or is larger than 64 KiB, and the file has none of the
  extensions `.key`, `.pub` and `.pqsig`, it tries `<file>.pqsig` instead.
- `util` (crate-only): key and signature path resolution (default `~/.pqsign/default.key`, `~` expansion) and the
  permission warnings for secret keys, password files and the secret key's directory. These only warn; they never
  fail. `mode_if_accessible_by_others` returns the mode instead of warning, for `change-password`'s note.

### `src/domain/`

- `KeyPair`, `SecretKey`, `PublicKey` wrap the `ed25519-dalek` and `fips204` ML-DSA-65 keys. A new key's ID is the
  first 8 bytes of its fingerprint.
- `SecretSeeds`: the two 32-byte seeds a new key is generated from, the RFC 8032 Ed25519 private key and the
  ML-DSA-65 seed ξ. `key_pair()` rebuilds the keys from them. It's the only input for writing secret key format v2.
- `Fingerprint`: BLAKE2b-256 over a domain tag and both public keys, displayed as `BLAKE2b-256:<base64>`.
- `Signature`, `SignatureFormat` (`V1`, `V2`): `SecretKey::sign` writes signature format v2; signature format v1
  only through `sign_as`.
- Fixed-size byte types for keys and signatures. The secret ones are wiped on drop, print as `[REDACTED]`, and
  cannot be cloned or compared.

### `src/format/`

- `FileHeader`, `FileType`: the `PQSN` header every binary file starts with.
- Public keys: one text line, `pqsign:v1:` plus base64. Secret keys: Argon2id + XChaCha20-Poly1305, parameters in
  `Kdf`; encoded only in secret key format v2, which stores the seeds, and read in format v1 too.
  `change_secret_key_password` (`change_password` in `secret_key.rs`) re-encrypts either format under a new
  password, keeping the header and the payload bytes. Reading is `parse` (every check that needs no password), then
  `decrypt` and `decode`; `seal` writes a header and everything after it for both writers. Before
  `change_password` replaces the file, it reads the new bytes back with the new password (`check_rewritten`) and
  checks that the file on disk is still the one it read (`check_unchanged`, `Error::KeyFileChanged`).
  Signatures: signature format v1 and v2 files, plus the trusted comment rules (`check_trusted_comment`).
- `inspect_file`: reads any pqsign file without decrypting a secret key or verifying a signature.
- `file` (internal): every read and write of a pqsign file goes through here.

### `src/errors.rs`, `src/password.rs`, `src/terminal.rs`

- `Error` is the one error type of the crate. `is_verification_failure` decides between exit codes 1 and 2.
- `PasswordSource` is `Prompt`, `Stdin`, `File(path)` or `Given(password)`. The command line never produces
  `Given`; the tests and benchmarks use it.
- `SafePath` and `SafeText` print text pqsign did not write itself, with control characters and bidirectional
  overrides escaped.

### Outside `src/`

- `benches/`: Criterion benchmarks in two targets, `crypto` (library types and the bare Ed25519 and ML-DSA-65
  operations) and `cli` (the command `run` functions end to end). Results are in [benchmarks.md](docs/benchmarks.md).
- `scripts/release-build.sh`: builds one release target reproducibly; the release workflow calls it, and
  [install.md](docs/install.md#rebuild-a-release-binary) explains how to rebuild a release with it.
- `tests/`: CLI and integration tests, fixtures for both signature formats and both secret key formats, and
  Wycheproof's ML-DSA-65 vectors.

## Invariants

These hold across module boundaries. A change that breaks one needs a deliberate decision, not just a code review.

- **Both signatures must verify.** `Signature::verify` checks the signer fingerprint (signature format v2 only) and
  the key ID first, then hashes the file and checks Ed25519, then ML-DSA-65, and stops at the first failure.
  ML-DSA-65 signs a message that contains the Ed25519 signature, so neither can be replaced on its own.
- **Exit codes.** 0 on success, 1 when a signature was checked and does not verify (`SignatureVerificationFailed`,
  `KeyIdMismatch`, `SignerMismatch`), 2 for everything else. clap exits with 2 by itself on a usage error, before
  any command runs.
- **No unsafe code.** `#![forbid(unsafe_code)]` in both `lib.rs` and `main.rs`.
- **Secrets are wiped.** Secret key bytes, passwords, the derived key and the Argon2id working memory are held in
  types that zeroize on drop. The release profile keeps `panic = "unwind"` so that `Drop` still runs on a panic.
  One known copy is out of reach: `fips204` takes the ML-DSA-65 secret key by value when a secret key format v1 key
  is loaded; a format v2 key hands it only a reference to the seed. Values moved on the stack and copies inside
  dependencies aren't wiped either, so this shortens how long secrets linger without guaranteeing that none
  remain. See [memory safety](docs/cryptography.md#memory-safety).
- **Nothing untrusted reaches the terminal raw.** Paths and error messages go through `SafePath` or `SafeText`.
  Trusted comments are rejected on write and on read if they contain a character `terminal::is_unsafe` flags, so
  they can be printed as they are.
- **Ask for the password last.** A secret key file's header, KDF parameters and length are checked before the
  first password is requested, and `sign` checks its input file, signature path and comment before that, so
  mistakes fail fast. `change-password` asks for the new password only after the current one has opened the file.
- **Bounded reads, atomic writes.** pqsign files larger than 64 KiB are rejected, and at most one byte more than
  that is read.
  Writes go to a temporary file next to the destination, which is synced and then renamed into place. A symlinked
  destination is resolved first, so its target is replaced and the link kept. Without `--overwrite`, the final
  rename never replaces an existing file, not even one created after the command checked.
  `write_key_pair` places the public key first and the secret key last, so if the last step fails the old secret
  key survives; without `--overwrite`, the public key it just placed is removed again.
- **File permissions (Unix).** Secret keys are exactly `0600`, also when `change-password` replaces one; public
  keys and signatures follow the umask; directories pqsign creates are at most `0700`.
- **KDF limits.** The command line always uses `Kdf::argon2id()` (256 MiB, 3 passes). Key files asking for more than
  1024 MiB or 16 passes are rejected, and pqsign never writes a key it would refuse to read.
- **Strict parsing, with two exceptions.** Signature format v2 files and secret key files in both formats reject
  trailing bytes. Signature format v1 files are read as leniently as pqsign 0.1 read them, and the binary data of a
  public key may continue after the ML-DSA-65 key; the text form of a public key must still be a single line.
- **Every secret key format stays readable.** pqsign encodes only secret key format v2; `change-password`
  re-encrypts a format v1 payload unchanged, and no format v1 encoder exists. Committed fixtures written by pqsign
  0.1.1, 0.3.1 and the release that introduced secret key format v2 keep both readable.
- **Seed derivation is frozen.** Secret key format v2 stores only the seeds and rebuilds the keys on every load
  (FIPS 204 `KeyGen_internal`, RFC 8032), so that derivation must never change. RFC 8032 and Wycheproof
  known-answer tests and the format v2 fixture pin it in a checkout of the repository; the published crate leaves
  the Wycheproof vectors out, and those tests then skip themselves. A different derivation needs a new secret key
  format version.

## Side effects

- **Files written:** the key pair (`~/.pqsign/default.key` and `.pub` by default), a secret key rewritten by
  `change-password`, signatures (`<file>.pqsig` by default), and temporary files named `.<name>.<random>.tmp` next
  to them while a write is in progress. The parent directory is synced afterwards, on Unix and best effort.
- **Files read:** the file being signed or verified, in full, for its BLAKE2b-512 hash; key and signature files;
  a password file up to its first line ending, including `--new-password-file`.
- **Terminal and standard input:** the password prompts, which for `change-password` are the current and the new
  password; standard input only with `--password-stdin`, which for `generate` gives the new key's password and
  for `change-password` only the current one.
- **Output:** results on stdout (the public key from `generate`, the report from `inspect`, the result of `verify`);
  status lines, warnings and errors on stderr.
- **Resources:** every secret key decryption runs Argon2id with the key file's parameters, and every encryption with
  the command line's defaults, 256 MiB and 3 passes; `change-password` runs it three times, once with the file's
  parameters and twice with the defaults. Key generation and every encryption draw from `rand::rng()`; ML-DSA-65
  signing is hedged and draws from the operating system's generator through `fips204`.
- **No network access.** Nothing in `src/` uses `std::net`, and no dependency in `Cargo.toml` is a network client.

## Testing

```bash
cargo test                # unit, integration and CLI tests
cargo bench --no-run      # compile the benchmarks; cargo test does not build them
```
