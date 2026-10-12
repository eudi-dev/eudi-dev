#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/examples/lib/public-ngrok.sh"
example_load_env_files "${REPO_ROOT}/.env" "${SCRIPT_DIR}/.env"
cleanup_enabled="false"
public_mode="false"
keycloak_ngrok_domain="${KEYCLOAK_NGROK_DOMAIN:-${NGROK_DOMAIN:-}}"
compose_args=(-f docker-compose.yml)
ngrok_override=""

ensure_oid4vc_dev() {
  if command -v eudi >/dev/null 2>&1; then
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    echo "Missing required command: go" >&2
    exit 1
  fi

  local gobin
  gobin="$(go env GOBIN)"
  if [[ -z "${gobin}" ]]; then
    gobin="$(go env GOPATH)/bin"
  fi
  mkdir -p "${gobin}"

  if ! command -v eudi-dev >/dev/null 2>&1; then
    echo "eudi not found. Installing latest with Go..."
    GOBIN="${gobin}" go install github.com/eudi-dev/eudi-dev/v2@latest
  fi
  export PATH="${gobin}:${PATH}"

  # go install builds the binary as eudi-dev, and the examples invoke `eudi`.
  if ! command -v eudi >/dev/null 2>&1; then
    ln -sf "$(command -v eudi-dev)" "${gobin}/eudi"
  fi
}

usage() {
  cat <<'EOF'
Usage: ./start.sh [--setup-only] [--public] [--domain <name>]

  default      Start Keycloak, bootstrap the issuer, and redeem a credential
  --setup-only Start Keycloak and bootstrap the issuer only
  --public     Publish Keycloak through ngrok and use the public HTTPS base URL everywhere
  --domain     Fixed ngrok hostname (otherwise detect from sandbox cert SAN when available)
EOF
}

cleanup() {
  if [[ "${cleanup_enabled}" == "true" ]]; then
    docker compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "${ngrok_override}" ]]; then
    rm -f "${ngrok_override}" >/dev/null 2>&1 || true
  fi
  example_stop_ngrok
}

mode="full"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-only) mode="setup-only" ;;
    --public) public_mode="true" ;;
    --domain)
      keycloak_ngrok_domain="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
  shift
done

cd "${SCRIPT_DIR}"

ensure_oid4vc_dev

if [[ "${public_mode}" == "true" ]]; then
  if [[ -z "${keycloak_ngrok_domain}" ]]; then
    keycloak_ngrok_domain="$(example_env_keycloak_ngrok_domain || true)"
  fi
  detected_domain="$(example_default_ngrok_domain "${REPO_ROOT}" "${SCRIPT_DIR}" "" || true)"
  if [[ -n "${detected_domain}" ]] && [[ "${detected_domain}" != "${keycloak_ngrok_domain}" ]]; then
    echo "Using ngrok hostname from sandbox certificate SAN: ${detected_domain}"
    keycloak_ngrok_domain="${detected_domain}"
  fi
  export KEYCLOAK_BASE_URL="$(example_start_ngrok_tunnel "keycloak-issuer-wallet" 8080 "${keycloak_ngrok_domain}")"
  ngrok_override="${SCRIPT_DIR}/docker-compose.ngrok.override.yml"
  example_write_keycloak_public_override "${ngrok_override}" "${KEYCLOAK_BASE_URL}"
  compose_args+=(-f "${ngrok_override}")
  echo "Keycloak public URL: ${KEYCLOAK_BASE_URL}"
else
  export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
fi

docker compose "${compose_args[@]}" up -d --force-recreate
./scripts/bootstrap.sh

if [[ "${mode}" == "full" ]]; then
  cleanup_enabled="true"
  trap cleanup EXIT INT TERM
  eudi wallet remove --all >/dev/null
  ./scripts/redeem-offer.sh
else
  echo
  echo "Issuer is ready."
fi
