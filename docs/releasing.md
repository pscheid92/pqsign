# Releasing

Releases are built, signed and published by the [release workflow](../.github/workflows/release.yml) when a version tag is pushed.

## Steps

1. Set the new version in `Cargo.toml`, run `cargo build` so `Cargo.lock` follows, and merge a `chore: release vX.Y.Z` commit to `main`.
2. Optionally, start a dry run from the Actions tab (Release, Run workflow) or with `gh workflow run release.yml`.
3. Tag the merged commit and push the tag:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

## What the workflow does

Each step only runs if the previous one succeeded:

1. Checks that the tag matches the version in `Cargo.toml`.
2. Runs the full CI suite: tests on Linux, macOS and Windows, tests with the minimum supported Rust version, clippy, rustfmt, actionlint, and `cargo audit` for dependencies with known vulnerabilities.
3. Builds the five release targets with `--locked` and the exact Rust version set in the workflow.
4. Signs every archive twice: `.pqsig` in the current format, and `.v1.pqsig` for pqsign 0.1, which cannot read format v2.
5. Verifies every signature against the committed `release.key.pub`. A release secret that does not match the committed key fails here.
6. Records build provenance for the archives as GitHub artifact attestations, then creates the GitHub release with the archives and signatures. Dry runs skip this step, so a real release is its first test. If it fails, nothing has been published, and the failed jobs can be re-run.
7. Publishes the crate to crates.io, last, because a published version can never be replaced.

A failing audit blocks the release. CI also runs every Monday, so a new advisory usually shows up before release day. Update the affected dependency, or, if the advisory does not affect pqsign, add its ID to `ignore` under `[advisories]` in `.cargo/audit.toml` with a comment saying why.

## Rust version

Release binaries are built with the Rust version in the build job of `release.yml`, not with whatever is stable on release day. Dependabot does not raise it. Before a release, raise it to the current stable in its own commit if it is behind, and let the dry run on that pull request build with it.

## Dry runs

Starting the workflow manually, or opening a pull request that changes `release.yml` or `ci.yml`, runs steps 1 to 5 with a throwaway key generated inside the run, so the release secrets are never used. Instead of steps 6 and 7 it runs `cargo publish --dry-run`. The signed files are kept as the `signed-release` workflow artifact.

## Secrets

| Secret | Content |
|---|---|
| `PQSIGN_SECRET_KEY` | The release secret key file, base64-encoded |
| `PQSIGN_PASSWORD` | Its password |
| `CARGO_REGISTRY_TOKEN` | A crates.io token with publish rights for `pqsign` |

Only real releases read them, and only in the steps that need them: the signing key in the sign job, the token in the publish job.
