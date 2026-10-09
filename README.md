# pqsign

Hybrid post-quantum file signing combining **Ed25519** and **ML-DSA-65**.

Both signatures must verify for a file to be considered authentic. This provides security against classical attacks today and quantum attacks in the future — if either algorithm holds, your signatures remain safe.

## Install

Download a prebuilt binary from the [latest release](https://github.com/pscheid92/pqsign/releases/latest), or build from source:

```bash
cargo install --path .
```

All release binaries are signed with pqsign itself. See [install & verification](docs/install.md) for details.

## Quick Start

```bash
# Generate a key pair (you'll be prompted for a password)
pqsign generate

# Sign a file
pqsign sign myfile.tar.gz

# Verify a signature
pqsign verify myfile.tar.gz
```

Keys default to `~/.pqsign/default.key` and `~/.pqsign/default.key.pub`. Signatures are written next to the file as `<file>.pqsig`.

## Usage

### Generate a key pair

```bash
pqsign generate                          # default path ~/.pqsign/default.key
pqsign generate -s mykey.key             # custom path
pqsign generate -s mykey.key --force     # overwrite existing
```

The public key is written alongside the secret key with a `.pub` extension as a single-line text string suitable for sharing:

```
pqsign:v1:UFFTTgEB...
```

### Sign a file

```bash
pqsign sign document.pdf
pqsign sign document.pdf -s mykey.key
pqsign sign document.pdf -t "release v1.0"       # custom trusted comment
pqsign sign document.pdf -x document.pdf.sig      # custom signature path
```

### Non-interactive use

`generate` and `sign` prompt for the secret key password on the terminal. Scripts and CI pass it explicitly instead:

```bash
pqsign sign document.pdf --password-stdin <<< "$PQSIGN_PASSWORD"   # first line of stdin
pqsign sign document.pdf --password-file ~/.pqsign/password        # first line of a file
pqsign generate -s ci.key --password-file ~/.pqsign/password      # no confirmation prompt
```

The password is the first line of the input without its line ending; other whitespace is kept. `--password-stdin` is meant for pipes: on a terminal the typed password is echoed. Without a terminal and without one of these options, the command fails with an error instead of reading standard input.

### Verify a signature

```bash
pqsign verify document.pdf
pqsign verify document.pdf -p mykey.key.pub
pqsign verify document.pdf -P "pqsign:v1:..."     # inline public key
pqsign verify document.pdf -q                      # quiet mode (exit code only)
```

Exits 0 if the signature is valid, 1 otherwise.

### Shell completions

```bash
pqsign completions bash > ~/.local/share/bash-completion/completions/pqsign
pqsign completions zsh > ~/.zfunc/_pqsign
pqsign completions fish > ~/.config/fish/completions/pqsign.fish
```

### Inspect files

```bash
pqsign inspect mykey.key.pub     # public key metadata
pqsign inspect mykey.key         # secret key metadata (KDF params)
pqsign inspect document.pdf.pqsig  # signature metadata
pqsign inspect document.pdf      # auto-finds document.pdf.pqsig
```

## How It Works

1. The file is hashed with **BLAKE2b-512** (streamed, never fully loaded into memory).
2. **Ed25519** signs `(context || hash || trusted_comment)`.
3. **ML-DSA-65** signs `(hash || ed25519_signature)` — nesting prevents selective signature replacement.
4. Verification requires both signatures to pass.

Secret keys are encrypted at rest with **Argon2id** (256 MiB, 3 iterations) + **XChaCha20-Poly1305**. Secret key material, passwords and the Argon2id working memory are wiped from memory after use; see [memory safety](docs/cryptography.md#memory-safety) for what that does and does not cover.

**Password guidance**: The Argon2id KDF makes brute-force expensive (~2.6 attempts/sec per core), but a weak password is still crackable. Use a passphrase of 4+ random words or a 20+ character random password from a password manager. See [brute-force resistance](docs/brute-force-resistance.md) for details.

## File Formats

| File | Format | Extension |
|---|---|---|
| Public key | Text (base64) | `.key.pub` |
| Secret key | Binary (encrypted) | `.key` |
| Signature | Binary | `.pqsig` |

All binary files start with magic bytes `PQSN`, a format version, and an 8-byte key ID for cross-referencing.

## Documentation

- [Install & verification](docs/install.md) — prebuilt binaries, build from source, signature verification
- [Cryptographic design](docs/cryptography.md) — algorithm choices, signature construction, key encryption
- [Benchmarks](docs/benchmarks.md) — performance of library and CLI operations
- [Brute-force resistance](docs/brute-force-resistance.md) — password cracking analysis with CPU and GPU estimates
- [KDF comparison](docs/kdf-comparison.md) — Argon2id parameter trade-offs

## License

[MIT](LICENSE)
