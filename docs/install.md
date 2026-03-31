# Install

## Prebuilt binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/pscheid92/pqsign/releases/latest):

| Platform | Archive |
|----------|---------|
| Linux x86_64 | `pqsign-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `pqsign-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 | `pqsign-x86_64-apple-darwin.tar.gz` |
| macOS ARM64 (Apple Silicon) | `pqsign-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `pqsign-x86_64-pc-windows-msvc.zip` |

Extract and place the binary somewhere in your `$PATH`.

## Build from source

```bash
cargo install --path .
```

Or from crates.io (once published):

```bash
cargo install pqsign
```

BSD and other platforms can build from source — the only requirement is a stable Rust toolchain.

## Verify release binaries

All release binaries are signed with pqsign itself. Each archive has a corresponding `.pqsig` signature file in the same release.

The release signing public key is [`release.key.pub`](../release.key.pub) in the repository root.

### With an existing pqsign install

```bash
# Download the binary and signature
curl -LO https://github.com/pscheid92/pqsign/releases/latest/download/pqsign-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/pscheid92/pqsign/releases/latest/download/pqsign-x86_64-unknown-linux-gnu.tar.gz.pqsig

# Verify using the public key file
pqsign verify pqsign-x86_64-unknown-linux-gnu.tar.gz -p release.key.pub
```

### With the inline public key

If you don't have the public key file, you can pass it inline:

```bash
pqsign verify pqsign-x86_64-unknown-linux-gnu.tar.gz -P "$(cat release.key.pub)"
```

### Public key

The release signing key is committed to the repository at [`release.key.pub`](../release.key.pub):

```
pqsign:v1:UFFTTgEBcL3P/MFgZGvXTtr/ofiml6mDUNKM4VJQO...
```

The full key is too long to display inline (post-quantum keys are large by nature — the ML-DSA-65 public key alone is 1952 bytes). Use the file directly for verification.
