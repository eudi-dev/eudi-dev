#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
SIBLING="${SCRIPT_DIR}/../keycloak-web-wallet"

if [[ $# -gt 0 ]]; then
  echo "Usage: $0" >&2
  echo "Optional environment: KEYCLOAK_PORT, APP_PORT, WALLET_BASE_URL," >&2
  echo "KEYCLOAK_PUBLIC_URL (skip ngrok), NGROK_DOMAIN (reserved ngrok domain)" >&2
  exit 1
fi

# Validate explicit ports. For defaults, choose a free port or reuse the port held by this
# project's Keycloak container.
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

resolve_port() { # resolve_port VAR DEFAULT
  local var="$1" def="$2" port
  if [[ -n "${!var:-}" ]]; then
    port="${!var}"
    if ! port_free "${port}"; then
      echo "${var}=${port} is set, but the port is already in use." >&2
      exit 1
    fi
  else
    port="${def}"
    while ! port_free "${port}"; do
      port=$((port + 1))
    done
    if [[ "${port}" -ne "${def}" ]]; then
      echo "Port ${def} is already in use. Using ${port} for ${var}."
    fi
  fi
  CLAIMED_PORTS+="${port} "
  printf -v "${var}" '%s' "${port}"
  # shellcheck disable=SC2163 # var holds the name of the variable to export
  export "${var}"
}

resolve_port KEYCLOAK_PORT 9080
resolve_port APP_PORT 9090

# The extension jar is shared with the local example.
if [[ ! -f "${SIBLING}/providers/keycloak-extension-oid4vp.jar" ]]; then
  "${SIBLING}/scripts/download-extension.sh"
fi

# The public wallet must reach Keycloak. Use KEYCLOAK_PUBLIC_URL when supplied or start an
# ngrok tunnel.
if [[ -z "${KEYCLOAK_PUBLIC_URL:-}" ]]; then
  if ! command -v ngrok >/dev/null 2>&1; then
    echo "ngrok is required (or set KEYCLOAK_PUBLIC_URL to a public https URL" >&2
    echo "that forwards to localhost:${KEYCLOAK_PORT}). Install: https://ngrok.com/download" >&2
    exit 1
  fi
  if [[ -f .ngrok.pid ]] && kill -0 "$(cat .ngrok.pid)" 2>/dev/null; then
    echo "Stopping the previous ngrok tunnel (pid $(cat .ngrok.pid))..."
    kill "$(cat .ngrok.pid)" 2>/dev/null || true
    sleep 1
  fi
  echo "Starting the ngrok tunnel for Keycloak (localhost:${KEYCLOAK_PORT})..."
  rm -f ngrok.log
  # Redirect both streams because ngrok outlives this script and would otherwise hold its
  # output pipes open.
  ngrok http "${KEYCLOAK_PORT}" ${NGROK_DOMAIN:+--domain="${NGROK_DOMAIN}"} \
    --log ngrok.log --log-format logfmt >/dev/null 2>&1 &
  echo $! > .ngrok.pid
  for _ in $(seq 1 30); do
    KEYCLOAK_PUBLIC_URL="$(grep -o 'url=https://[^ ]*' ngrok.log 2>/dev/null | head -1 | cut -d= -f2 || true)"
    [[ -n "${KEYCLOAK_PUBLIC_URL}" ]] && break
    if ! kill -0 "$(cat .ngrok.pid)" 2>/dev/null; then
      echo "ngrok exited during startup, see ngrok.log:" >&2
      tail -5 ngrok.log >&2 || true
      exit 1
    fi
    sleep 1
  done
  if [[ -z "${KEYCLOAK_PUBLIC_URL}" ]]; then
    echo "Timed out waiting for the ngrok tunnel URL, see ngrok.log" >&2
    exit 1
  fi
  echo "Tunnel: ${KEYCLOAK_PUBLIC_URL} -> localhost:${KEYCLOAK_PORT}"
fi
export KEYCLOAK_PUBLIC_URL="${KEYCLOAK_PUBLIC_URL%/}"
export WALLET_BASE_URL="${WALLET_BASE_URL:-https://eudi-test.dev}"

echo "Starting Keycloak and the demo UI..."
docker compose up -d --build keycloak app

echo "Waiting for the services to become ready..."
docker compose run --rm --entrypoint sh demo /scripts/wait-ready.sh

echo "Checking that Keycloak is reachable through the public URL..."
if ! curl -fs -o /dev/null "${KEYCLOAK_PUBLIC_URL}/realms/wallet-demo/.well-known/openid-configuration"; then
  echo "Keycloak is not reachable at ${KEYCLOAK_PUBLIC_URL}." >&2
  echo "Check the tunnel (ngrok.log) or your KEYCLOAK_PUBLIC_URL forwarding." >&2
  exit 1
fi

echo "Configuring the verifier's wallet links (walletScheme, trustListUrl)..."
docker compose run --rm demo configure-wallet-links.py

echo
echo "Ready."
echo "  Demo UI:        http://localhost:${APP_PORT}"
echo "  Keycloak:       ${KEYCLOAK_PUBLIC_URL} (public) / http://localhost:${KEYCLOAK_PORT} (local)"
echo "  Wallet:         ${WALLET_BASE_URL} (shared public demo, auto-accept, daily reset)"
echo
echo "Stop with: docker compose down"
if [[ -f .ngrok.pid ]]; then
  echo "           kill \$(cat .ngrok.pid)   # ngrok tunnel"
fi
