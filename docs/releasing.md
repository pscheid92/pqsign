# Releasing

Releases are built, signed and published by the [release workflow](../.github/workflows/release.yml) when a version tag is pushed. This guide walks through one release from start to finish; `X.Y.Z` stands for the new version, for example `0.3.1`.

## Before you start

- `gh` is signed in with push rights to `pscheid92/pqsign` and `pscheid92/homebrew-tap`.
- Git signs tags: `git config tag.gpgsign` prints `true`, with an SSH or GPG signing key set up. Since v0.3.0, every release tag is signed.
- `cargo-audit` is installed (`cargo install cargo-audit`), and a released pqsign is on your `PATH` to verify the downloads.
- Everything that should go into the release is merged to `main`, and CI on `main` is green. CI also runs every Monday, so a new advisory usually shows up before release day; see [audit failures](#audit-failures).

## 1. Prepare the release pull request

On a branch from an up-to-date `main`, set the new version in `Cargo.toml` and let `Cargo.lock` follow:

```bash
git switch main && git pull --ff-only
git switch -c claude/release-vX.Y.Z
# edit Cargo.toml: version = "X.Y.Z"
cargo build
```

Only those two files change. Run what the release workflow will run, plus the publish dry run:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo audit
cargo publish --dry-run --locked --allow-dirty
```

`cargo publish --dry-run` warns that the benchmarks are not in the package; that is expected, since `benches/` is in `exclude`.

Commit as `chore: release vX.Y.Z`, push, and open a pull request with the same title. Its description says what to do after the merge and lists what the release contains since the last tag:

```bash
git log vPREVIOUS..main --no-merges --format='%h %s'
```

Optionally, run the release workflow on the branch before merging. A dry run builds, signs and verifies everything with a throwaway key and ends with `cargo publish --dry-run`; see [dry runs](#dry-runs):

```bash
gh workflow run release.yml --ref claude/release-vX.Y.Z
```

## 2. Tag the merge commit

After the pull request is merged, tag its merge commit on `main` with a signed, annotated tag whose message is `pqsign X.Y.Z`:

```bash
git switch main && git pull --ff-only
git log --oneline -1        # the merge commit of the release pull request
git tag -s -m "pqsign X.Y.Z" vX.Y.Z
git cat-file tag vX.Y.Z     # shows the message and a -----BEGIN SSH SIGNATURE----- block
```

The workflow fails right away if the tag does not match the version in `Cargo.toml`. It does not check the tag's signature; the signature is for people who check the tag.

## 3. Push the tag and watch the workflow

Pushing the tag starts the release:

```bash
git push origin vX.Y.Z
gh run watch "$(gh run list --workflow release.yml --event push --limit 1 --json databaseId -q '.[0].databaseId')"
```

A full run takes about five to ten minutes. The jobs run in this order, and each only if the previous one succeeded: version check, CI, build, sign, GitHub release, crates.io publish. See [what the workflow does](#what-the-workflow-does).

If a job fails:

- **Before the GitHub release job**, nothing has been published. Fix the cause and re-run the failed jobs with `gh run rerun --failed <run-id>`. If the fix needs a new commit, delete the tag (`git push origin :refs/tags/vX.Y.Z` and `git tag -d vX.Y.Z`), merge the fix, and tag again.
- **In the publish job**, the GitHub release already exists. Re-run only the failed job. Do not delete or move the tag: the release and its attestations name that commit.
- A version on crates.io can never be replaced. If a published release is broken, release a new patch version, and yank the broken one only if it is harmful: `cargo yank --version X.Y.Z`.

## 4. Write the release notes

The workflow creates the release with notes GitHub generates from the merged pull requests. Replace them with notes written for users:

```bash
gh release edit vX.Y.Z --notes-file release-notes.md
```

Earlier releases follow this outline, with only the sections that apply:

- One or two sentences on what the release is about, and whether commands, output, exit codes and file formats changed.
- **Behaviour changes**: anything a user or script could notice.
- **Security fixes**, in pqsign or its dependencies, with advisory IDs, and whether pqsign was affected.
- **Under the hood** and **Documentation**: smaller changes worth knowing.
- **Verifying this release**, kept as in the previous release: the release key fingerprint `BLAKE2b-256:tgolgaKRfSGSvflaZqCjVtX+YXy6I+/tgvAbOW/npIc`, and the `pqsign verify` and `gh attestation verify` commands from [install.md](install.md#verify-release-binaries). Links into the repository point at the tag, as in `blob/vX.Y.Z/docs/install.md`, so they keep working.

## 5. Check the published release

From the repository root, which holds `release.key.pub`, download the release and check it the way a user would:

```bash
dir=$(mktemp -d)
gh release download vX.Y.Z --dir "$dir"
for archive in "$dir"/*.tar.gz "$dir"/*.zip; do pqsign verify "$archive" -p release.key.pub -q && echo "ok  $archive"; done
gh attestation verify "$dir/pqsign-x86_64-unknown-linux-gnu.tar.gz" --repo pscheid92/pqsign \
  --signer-workflow pscheid92/pqsign/.github/workflows/release.yml
```

Then check that the binary for your platform reports the new version and that its embedded dependency list has no known advisories:

```bash
tar -xzf "$dir/pqsign-aarch64-apple-darwin.tar.gz" -C "$dir"
"$dir/pqsign" --version     # pqsign X.Y.Z
cargo audit bin "$dir/pqsign"
```

Finally, check that crates.io lists the new version: `cargo search pqsign --limit 1`.

## 6. Update the Homebrew cask

Nothing updates the cask automatically, because pqsign does not use GoReleaser. In pscheid92/homebrew-tap, [`Casks/pqsign.rb`](https://github.com/pscheid92/homebrew-tap/blob/main/Casks/pqsign.rb) needs the new `version` and the `sha256` of the four macOS and Linux archives. Take the checksums from the archives whose signatures you verified in step 5:

```bash
shasum -a 256 "$dir"/*.tar.gz
```

| Cask block | Archive |
|---|---|
| `on_macos` / `on_arm` | `pqsign-aarch64-apple-darwin.tar.gz` |
| `on_macos` / `on_intel` | `pqsign-x86_64-apple-darwin.tar.gz` |
| `on_linux` / `on_arm` | `pqsign-aarch64-unknown-linux-gnu.tar.gz` |
| `on_linux` / `on_intel` | `pqsign-x86_64-unknown-linux-gnu.tar.gz` |

After the change is merged, check the cask on a Mac:

```bash
brew update && brew upgrade pqsign && pqsign --version
```

## 7. Clean up

Delete the merged release branch locally (`git branch -d claude/release-vX.Y.Z`); GitHub deletes the remote branch on merge. Remove the download directory from step 5.

## What the workflow does

Each step only runs if the previous one succeeded:

1. Checks that the tag matches the version in `Cargo.toml`.
2. Runs the full CI suite: tests on Linux, macOS and Windows, tests with the minimum supported Rust version, clippy, rustfmt, actionlint, and `cargo audit` for dependencies with known vulnerabilities.
3. Builds the five release targets with `--locked`, the exact Rust version set in the workflow and [`scripts/release-build.sh`](../scripts/release-build.sh), which keeps build paths out of the binary and embeds the dependency list with cargo-auditable. Each target is built a second time from another directory, and the job fails if the two binaries differ. A CycloneDX SBOM is written per target.
4. Signs every archive and SBOM with a `.pqsig` in the current format, and every archive also with a `.v1.pqsig` for pqsign 0.1, which cannot read format v2.
5. Verifies every signature against the committed `release.key.pub`. A release secret that does not match the committed key fails here.
6. Records build provenance for the archives as GitHub artifact attestations, then creates the GitHub release with the archives and signatures. Dry runs skip this step, so a real release is its first test. If it fails, nothing has been published, and the failed jobs can be re-run.
7. Publishes the crate to crates.io, last, because a published version can never be replaced.

### Audit failures

A failing audit blocks the release. Update the affected dependency, or, if the advisory does not affect pqsign, add its ID to `ignore` under `[advisories]` in `.cargo/audit.toml`, which does not exist yet, with a comment saying why.

## Rust version

Release binaries are built with the Rust version in the build job of `release.yml`, not with whatever is stable on release day. When a new Rust version comes out, Renovate proposes it in its own pull request, which also updates the rebuild instructions in `docs/install.md`; the dry run on that pull request builds the release with it. Merge it before a release if the release should use it. Renovate does the same for cargo-auditable and cargo-cyclonedx, which the same job installs.

## Dry runs

Starting the workflow manually, or opening a pull request that changes `release.yml` or `ci.yml`, runs steps 1 to 5 with a throwaway key generated inside the run, so the release secrets are never used. Instead of steps 6 and 7 it runs `cargo publish --dry-run`. The signed files are kept as the `signed-release` workflow artifact.

## Secrets

| Secret | Content |
|---|---|
| `PQSIGN_SECRET_KEY` | The release secret key file, base64-encoded |
| `PQSIGN_PASSWORD` | Its password |
| `CARGO_REGISTRY_TOKEN` | A crates.io token with publish rights for `pqsign` |

Only real releases read them, and only in the steps that need them: the signing key in the sign job, the token in the publish job.
