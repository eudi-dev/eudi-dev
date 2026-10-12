#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

SETUP_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --setup-only) SETUP_ONLY=true ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: $0 [--setup-only]" >&2
      exit 1
      ;;
  esac
done

# Published ports must match listener ports. Defaults use the 9xxx range to avoid common
# wallet and Keycloak ports. Reuse this project's existing bindings and select free ports
# otherwise.

port_listening() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

port_is_ours() {
  local mapping
  mapping="$(docker compose port keycloak "$1" 2>/dev/null || true)"
  [[ -n "${mapping}" && "${mapping}" != *:0 ]]
}

CLAIMED_PORTS=" "
port_free() {
  [[ "${CLAIMED_PORTS}" != *" $1 "* ]] || return 1
  ! port_listening "$1" || port_is_ours "$1"
}

resolve_port() { # resolve_port VAR DEFAULT [SPAN]
  local var="$1" def="$2" span="${3:-1}" port offset all_free
  if [[ -n "${!var:-}" ]]; then
    port="${!var}"
    for ((offset = 0; offset < span; offset++)); do
      if ! port_free "$((port + offset))"; then
        echo "${var}=${port} is set, but port $((port + offset)) is already in use." >&2
        exit 1
      fi
    done
  else
    port="${def}"
    while :; do
      all_free=true
      for ((offset = 0; offset < span; offset++)); do
        port_free "$((port + offset))" || { all_free=false; break; }
      done
      [[ "${all_free}" == "true" ]] && break
      port=$((port + 1))
    done
    if [[ "${port}" -ne "${def}" ]]; then
      echo "Port ${def} is already in use. Using ${port} for ${var}."
    fi
  fi
  for ((offset = 0; offset < span; offset++)); do
    CLAIMED_PORTS+="$((port + offset)) "
  done
  printf -v "${var}" '%s' "${port}"
  # shellcheck disable=SC2163 # var holds the name of the variable to export
  export "${var}"
}

resolve_port KEYCLOAK_PORT 9080
# The wallet also serves HTTPS on WALLET_PORT+1 inside the shared network
# namespace (status-list endpoint), so it needs two consecutive ports.
resolve_port WALLET_PORT 9085 2
resolve_port APP_PORT 9090

# Prefer a local verifier extension checkout so unreleased changes can be tested.
EXTENSION_REPO="${KEYCLOAK_OID4VP_REPO:-${SCRIPT_DIR}/../../../keycloak-extension-oid4vp}"
if [[ ! -f providers/keycloak-extension-oid4vp.jar ]]; then
  if [[ -d "${EXTENSION_REPO}" ]] && command -v mvn >/dev/null 2>&1; then
    echo "Building keycloak-extension-oid4vp snapshot from ${EXTENSION_REPO}..."
    (cd "${EXTENSION_REPO}" && mvn -q -pl core -am package -DskipTests)
    cp "${EXTENSION_REPO}/core/target/keycloak-extension-oid4vp.jar" providers/
  elif ! ./scripts/download-extension.sh; then
    echo >&2
    echo "No local keycloak-extension-oid4vp checkout found and the download failed." >&2
    echo "Set KEYCLOAK_OID4VP_REPO to a keycloak-extension-oid4vp checkout," >&2
    echo "or build the jar there (mvn -pl core -am package -DskipTests) and copy" >&2
    echo "core/target/keycloak-extension-oid4vp.jar into providers/." >&2
    exit 1
  fi
fi

echo "Exporting the wallet CA certificate for Keycloak's truststore..."
docker compose build wallet-init
current_ca="$(docker compose run --rm -T wallet-init trust ca-cert)"
compose_up_flags=""
if [[ ! -f wallet-ca-cert.pem ]] || [[ "$(cat wallet-ca-cert.pem)" != "${current_ca}" ]]; then
  # Keycloak reads its truststore at startup. Recreate containers when the wallet CA
  # changes.
  printf '%s\n' "${current_ca}" > wallet-ca-cert.pem
  compose_up_flags="--force-recreate"
fi

echo "Starting Keycloak, the wallet, and the demo UI..."
docker compose up -d --build ${compose_up_flags} keycloak wallet app

echo "Waiting for the services to become ready..."
docker compose run --rm --entrypoint sh demo /scripts/wait-ready.sh

echo "Configuring the verifier's wallet links (walletScheme, trustListUrl)..."
docker compose run --rm demo configure-wallet-links.py

if [[ "${SETUP_ONLY}" == "true" ]]; then
  echo
  echo "Setup complete. Run the demos with:"
  echo "  docker compose run --rm demo demo-issuance.py"
  echo "  docker compose run --rm demo demo-verification.py"
  exit 0
fi

echo
echo "=== Issuance via wallet URL ==="
docker compose run --rm demo demo-issuance.py

echo
echo "=== Verification via wallet URL ==="
docker compose run --rm demo demo-verification.py

echo
echo "Demo UI: http://localhost:${APP_PORT:-9090}"
