#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
require_eudi_dev() {
  if command -v eudi >/dev/null 2>&1; then
    return 0
  fi
  echo "eudi not found in PATH. Install it first or run ./start.sh." >&2
  exit 1
}

require_eudi_dev
OFFER_URI="$("${SCRIPT_DIR}/create-offer.sh")"

echo "Redeeming offer:"
echo "  ${OFFER_URI}"

eudi wallet accept "${OFFER_URI}"

echo
echo "Stored credentials:"
eudi wallet list
