#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

WALLET_PORT="${OID4VC_WALLET_PORT:-8087}"
APP_PORT="${APP_PORT:-8090}"
APP_PID=""
WALLET_PID=""
KEYCLOAK_LOGS_PID=""

export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
export KEYCLOAK_REALM="${KEYCLOAK_REALM:-wallet-app-demo}"
export OID4VC_WALLET_PORT="${WALLET_PORT}"

usage() {
  cat <<'EOF'
Usage: ./start.sh [--app|--smoke|--setup-only]

  --app         Start Keycloak, the wallet, and the demo app, then wait (default)
  --smoke       Run the headless subject-binding login check after setup
  --setup-only  Start Keycloak and the wallet, then leave them running
EOF
}

ensure_oid4vc_dev() {
  if command -v eudi >/dev/null 2>&1; then
    return 0
  fi
  command -v go >/dev/null 2>&1 || { echo "Missing required command: go" >&2; exit 1; }
  local gobin
  gobin="$(go env GOBIN)"
  [[ -z "${gobin}" ]] && gobin="$(go env GOPATH)/bin"
  mkdir -p "${gobin}"
  if ! command -v eudi-dev >/dev/null 2>&1; then
    echo "eudi not found. Installing latest with Go..."
    GOBIN="${gobin}" go install github.com/eudi-dev/eudi-dev/v3@latest
  fi
  export PATH="${gobin}:${PATH}"
  command -v eudi >/dev/null 2>&1 || ln -sf "$(command -v eudi-dev)" "${gobin}/eudi"
}

cleanup() {
  [[ -n "${APP_PID}" ]] && { kill "${APP_PID}" >/dev/null 2>&1 || true; }
  [[ -n "${WALLET_PID}" ]] && { kill "${WALLET_PID}" >/dev/null 2>&1 || true; }
  [[ -n "${KEYCLOAK_LOGS_PID}" ]] && { kill "${KEYCLOAK_LOGS_PID}" >/dev/null 2>&1 || true; }
  docker compose -f "${SCRIPT_DIR}/docker-compose.yml" down --remove-orphans >/dev/null 2>&1 || true
}

mode="app"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) mode="app" ;;
    --smoke) mode="smoke" ;;
    --setup-only) mode="setup-only" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
  esac
  shift
done

cd "${SCRIPT_DIR}"
ensure_oid4vc_dev
./scripts/download-extension.sh

# Use host.docker.internal so Keycloak can fetch wallet trust and status lists from its
# container. Add the wallet CA to its truststore.
echo "Seeding the wallet with a PID..."
eudi wallet remove --all >/dev/null 2>&1 || true
eudi issue sdjwt --wallet --pid --iss "https://host.docker.internal:$((WALLET_PORT + 1))" >/dev/null
eudi trust ca-cert --out "${SCRIPT_DIR}/wallet-ca-cert.pem" >/dev/null

echo "Starting the wallet on port ${WALLET_PORT}..."
eudi wallet serve --docker --port "${WALLET_PORT}" &
WALLET_PID=$!

echo "Recreating Keycloak from the realm import..."
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --force-recreate

./scripts/bootstrap.sh

case "${mode}" in
  smoke)
    trap cleanup EXIT INT TERM
    ./scripts/smoke.py
    ;;
  app)
    trap cleanup EXIT INT TERM
    docker compose logs -f --tail=40 keycloak &
    KEYCLOAK_LOGS_PID=$!
    ./scripts/start-app.sh &
    APP_PID=$!
    for _ in $(seq 1 60); do
      curl -fsS "http://127.0.0.1:${APP_PORT}/healthz" >/dev/null 2>&1 && break
      sleep 1
    done
    echo
    echo "Open the demo app: http://127.0.0.1:${APP_PORT}"
    echo "Sign in with the wallet. The first login asks for the alice / alice password"
    echo "and issues the membership credential. The next login is passwordless."
    wait "${APP_PID}"
    ;;
  setup-only)
    disown "${WALLET_PID}" 2>/dev/null || true
    echo
    echo "Keycloak and the wallet are running."
    echo "  Drive a login: ./scripts/smoke.py"
    echo "  Stop:          docker compose down -v && eudi wallet kill ${WALLET_PORT}"
    ;;
esac
