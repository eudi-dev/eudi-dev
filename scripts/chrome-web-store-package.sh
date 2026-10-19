#!/usr/bin/env bash
# Builds the Chrome Web Store package of the browser extension for a release.
# The manifest version comes from the release version, and the extension uses
# the public demo by default. Prints the path of the zip.
#
# Usage: scripts/chrome-web-store-package.sh v3.3.0 [output.zip]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

version="${1:-}"
# The store rejects a version it has seen, so prereleases don't get a package.
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH [output.zip]" >&2
  exit 2
fi
out="${2:-$PROJECT_DIR/dist/eudi-dev-dc-api-extension-${version#v}.zip}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$PROJECT_DIR" && go build -ldflags "-X github.com/eudi-dev/eudi-dev/v3/cmd.Version=$version" -o "$work/eudi" .)
EUDI_DEV_HOME="$work/home" "$work/eudi" wallet extension "$work/extension" >/dev/null

mkdir -p "$(dirname "$out")"
out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
rm -f "$out"
(cd "$work/extension" && zip -qrX "$out" .)
echo "$out"
