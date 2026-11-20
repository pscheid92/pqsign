#!/usr/bin/env bash
# Updates Casks/pqsign.rb in a homebrew-tap checkout for a published release: the version, and the sha256 of each
# macOS and Linux archive, taken from archives whose signatures verify against release.key.pub.
#
# Usage, from the repository root: scripts/update-cask.sh X.Y.Z path/to/homebrew-tap
#
# Needs gh and a released pqsign on PATH. It changes only the cask file; committing and opening the pull request is
# left to you.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 X.Y.Z path/to/homebrew-tap" >&2
  exit 2
fi
version=$1
cask="$2/Casks/pqsign.rb"
targets=(aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu)

[[ -f release.key.pub ]] || { echo "run this from the pqsign repository root, which holds release.key.pub" >&2; exit 2; }
[[ -f $cask ]] || { echo "$cask not found" >&2; exit 2; }

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

checksums=()
for target in "${targets[@]}"; do
  archive="pqsign-$target.tar.gz"
  gh release download "v$version" --repo pscheid92/pqsign --dir "$dir" --pattern "$archive" --pattern "$archive.pqsig"
  pqsign verify "$dir/$archive" -p release.key.pub -q
  sha=$(shasum -a 256 "$dir/$archive" | cut -d ' ' -f 1)
  echo "ok  $archive  $sha"
  checksums+=("$target=$sha")
done

# Each sha256 line sits right before the url line that names its archive, so the archive name decides which
# checksum goes where, not the order of the blocks.
awk -v version="$version" -v map="${checksums[*]}" '
  BEGIN {
    n = split(map, pairs, " ")
    for (i = 1; i <= n; i++) {
      split(pairs[i], kv, "=")
      sha[kv[1]] = kv[2]
    }
  }
  { line[NR] = $0 }
  END {
    for (i = 1; i <= NR; i++) {
      out = line[i]
      if (out ~ /^  version "/) {
        sub(/"[^"]*"/, "\"" version "\"", out)
        versioned = 1
      }
      if (out ~ /sha256 "/ && i < NR) {
        for (t in sha) {
          if (index(line[i + 1], "pqsign-" t ".tar.gz")) {
            sub(/sha256 "[0-9a-f]*"/, "sha256 \"" sha[t] "\"", out)
            done[t] = 1
          }
        }
      }
      print out
    }
    if (!versioned) { print "no version line in the cask" > "/dev/stderr"; exit 1 }
    for (t in sha) if (!(t in done)) { print "no sha256 line before the url of " t > "/dev/stderr"; exit 1 }
  }
' "$cask" > "$dir/pqsign.rb"
mv "$dir/pqsign.rb" "$cask"

echo
echo "Updated $cask to $version:"
git -C "$2" diff --stat
