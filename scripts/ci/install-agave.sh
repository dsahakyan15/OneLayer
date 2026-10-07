#!/usr/bin/env bash
# Local-validator CI tooling only. No wallet, RPC or chain mutation.
# Release and digest from the official anza-xyz/agave v3.1.10 release assets:
# https://github.com/anza-xyz/agave/releases/tag/v3.1.10
set -euo pipefail

destination=${1:?Usage: install-agave.sh ABSOLUTE_EMPTY_DIRECTORY}
[[ "$destination" == /* ]] || { echo "installation directory must be absolute" >&2; exit 2; }
[[ ! -e "$destination" ]] || { echo "installation directory already exists" >&2; exit 2; }
archive_dir=$(mktemp -d)
trap 'rm -rf -- "$archive_dir"' EXIT
archive="$archive_dir/agave.tar.bz2"
curl --fail --location --retry 3 --max-time 300 \
  https://github.com/anza-xyz/agave/releases/download/v3.1.10/solana-release-x86_64-unknown-linux-gnu.tar.bz2 \
  --output "$archive"
printf '%s  %s\n' a7205ff29bcf0f7199740225ecae2b85a28ea9668892d5ec21bd9749882984a1 "$archive" | sha256sum --check --strict
mkdir -p -- "$destination"
tar --extract --bzip2 --file "$archive" --directory "$destination" --no-same-owner
bin="$destination/solana-release/bin"
"$bin/solana" --version
"$bin/solana-test-validator" --version
"$bin/cargo-build-sbf" --version
export PATH="$bin:$PATH"
cargo build-sbf --install-only --tools-version v1.52
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$bin" >> "$GITHUB_PATH"
fi
