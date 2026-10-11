#!/usr/bin/env bash
# Builds the release binary for one target exactly as the release workflow does, so anyone can rebuild a release
# and compare the bytes (docs/install.md). Needs the Rust version named in release.yml and cargo-auditable.
#
# Usage: scripts/release-build.sh <target>
set -euo pipefail

target=${1:?usage: scripts/release-build.sh <target>}

# Git Bash on Windows rewrites arguments and variables that look like Unix paths, such as /Brepro or =/cargo
# below, before cargo sees them. Elsewhere these variables mean nothing.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' MSYS2_ENV_CONV_EXCL='*'

# Panic messages of dependencies carry their source paths, which lie under the Cargo home. Remapping it keeps the
# home directory of whoever builds out of the binary.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
if command -v cygpath >/dev/null; then
  cargo_home=$(cygpath -w "$cargo_home")
fi
rustflags="--remap-path-prefix=$cargo_home=/cargo"

case "$target" in
  # The macOS linker derives the binary's UUID from debug information that names the object files in target/,
  # before rustc strips that information. Without it, the UUID no longer depends on where the build ran.
  *-apple-darwin) rustflags+=" -C link-arg=-Wl,-S" ;;
  # The MSVC linker stamps the build time into the binary unless told to be deterministic.
  *-windows-msvc) rustflags+=" -C link-arg=/Brepro" ;;
esac

# cargo-auditable embeds the dependency list, so `cargo audit bin` and other scanners can check the binary.
RUSTFLAGS=$rustflags cargo auditable build --release --locked --target "$target"
