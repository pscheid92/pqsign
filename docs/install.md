# Install

## Homebrew

On macOS and Linux:

```bash
brew install pscheid92/tap/pqsign
```

The [cask](https://github.com/pscheid92/homebrew-tap/blob/main/Casks/pqsign.rb) installs the prebuilt release archive for your platform. Homebrew checks the download against the checksum in the cask, not against the pqsign signature. To check the signature too, download the archive and follow [Verify release binaries](#verify-release-binaries). The macOS binaries are not notarized, so the cask removes the quarantine flag that would make Gatekeeper block them.

`brew upgrade pqsign` installs new releases.

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

From crates.io:

```bash
cargo install --locked pqsign
```

`--locked` builds with the exact dependency versions pqsign was tested and released with. Cargo builds from the source published on crates.io; the pqsign signatures described below cover the prebuilt archives only.

Or from a checkout of this repository:

```bash
cargo install --locked --path .
```

BSD and other platforms can build from source — the only requirement is Rust 1.88 or newer.

## Verify release binaries

All release binaries are signed with pqsign itself. Each archive has a corresponding `.pqsig` signature file in the same release, and a `.v1.pqsig` file for pqsign 0.1, which cannot read the newer signature format.

The release signing public key is [`release.key.pub`](../release.key.pub) in the repository root.

### With an existing pqsign install

```bash
# Download the binary and signature
curl -LO https://github.com/pscheid92/pqsign/releases/latest/download/pqsign-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/pscheid92/pqsign/releases/latest/download/pqsign-x86_64-unknown-linux-gnu.tar.gz.pqsig

# Verify using the public key file
pqsign verify pqsign-x86_64-unknown-linux-gnu.tar.gz -p release.key.pub
```

### With pqsign 0.1

pqsign 0.1 rejects the current signature format with "file requires pqsign format v2". Verify the download with the `.v1.pqsig` file instead, then upgrade:

```bash
curl -LO https://github.com/pscheid92/pqsign/releases/latest/download/pqsign-x86_64-unknown-linux-gnu.tar.gz.v1.pqsig
pqsign verify pqsign-x86_64-unknown-linux-gnu.tar.gz -p release.key.pub -x pqsign-x86_64-unknown-linux-gnu.tar.gz.v1.pqsig
```

### With the inline public key

If you don't have the public key file, you can pass it inline:

```bash
pqsign verify pqsign-x86_64-unknown-linux-gnu.tar.gz -P "$(cat release.key.pub)"
```

### Check the release key

The release signing key is committed to the repository at [`release.key.pub`](../release.key.pub). Before trusting it, check its fingerprint:

```bash
pqsign inspect release.key.pub
```

The output must show exactly this fingerprint:

```
Fingerprint: BLAKE2b-256:tgolgaKRfSGSvflaZqCjVtX+YXy6I+/tgvAbOW/npIc
```

`verify` prints the fingerprint of the key it used, too. Compare the whole fingerprint rather than the key ID or the start of the key string: another key can carry the same key ID and share its first characters. pqsign 0.1 does not show fingerprints; compare the downloaded `release.key.pub` with the copy in this repository instead.

### Check where a binary was built

Releases after 0.1.1 also carry a build provenance attestation for each archive: a record of the workflow run, commit and tag that built it, signed through [Sigstore](https://www.sigstore.dev/) and stored by GitHub. Check it with the [GitHub CLI](https://cli.github.com/):

```bash
gh attestation verify pqsign-x86_64-unknown-linux-gnu.tar.gz --repo pscheid92/pqsign --signer-workflow pscheid92/pqsign/.github/workflows/release.yml
```

It complements the pqsign signature rather than replacing it. The attestation is signed with a short-lived certificate that Sigstore issued to the release workflow, so it shows where the archive was built. The `.pqsig` file shows that the release key signed it.
