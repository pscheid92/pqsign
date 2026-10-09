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
2. Runs the full CI suite: tests on Linux, macOS and Windows, clippy, rustfmt and actionlint.
3. Builds the five release targets with `--locked`.
4. Signs every archive twice: `.pqsig` in the current format, and `.v1.pqsig` for pqsign 0.1, which cannot read format v2.
5. Verifies every signature against the committed `release.key.pub`. A release secret that does not match the committed key fails here.
6. Creates the GitHub release with the archives and signatures.
7. Publishes the crate to crates.io, last, because a published version can never be replaced.

## Dry runs

Starting the workflow manually, or opening a pull request that changes `release.yml` or `ci.yml`, runs steps 1 to 5 with a throwaway key generated inside the run, so the release secrets are never used. Instead of steps 6 and 7 it runs `cargo publish --dry-run`. The signed files are kept as the `signed-release` workflow artifact.

## Secrets

| Secret | Content |
|---|---|
| `PQSIGN_SECRET_KEY` | The release secret key file, base64-encoded |
| `PQSIGN_PASSWORD` | Its password |
| `CARGO_REGISTRY_TOKEN` | A crates.io token with publish rights for `pqsign` |

Only real releases read them, and only in the steps that need them: the signing key in the sign job, the token in the publish job.
