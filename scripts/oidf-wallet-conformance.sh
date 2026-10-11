#!/bin/sh
set -eu

unset CDPATH
ROOT_DIR=$(cd -- "$(dirname -- "$0")/.." && pwd)

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$ROOT_DIR/.env"
  set +a
fi

. "$ROOT_DIR/scripts/oidf-conformance-lib.sh"

PORT=${PORT:-$(pick_port_pair)}
RUN_DIR=${OIDF_RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/oidf-wallet-conformance.XXXXXX")}
WALLET_DIR=${OIDF_WALLET_DIR:-"$RUN_DIR/wallet"}
# OIDF_WALLET_URL selects an externally managed wallet, so the wrapper does not start one.
WALLET_MANAGED=1
if [ -n "${OIDF_WALLET_URL:-}" ]; then
  WALLET_MANAGED=0
fi
# Use a separate home so ordinary instance commands do not stop or reconfigure the test
# wallet.
if [ "$WALLET_MANAGED" = "1" ]; then
  EUDI_DEV_HOME=${EUDI_DEV_HOME:-"$RUN_DIR/home"}
  export EUDI_DEV_HOME
fi
WALLET_URL=${OIDF_WALLET_URL:-"http://127.0.0.1:${PORT}"}
# The hosted suite needs a public HTTPS origin to fetch wallet metadata and status lists.
# A tunnel can terminate TLS in front of the local port.
WALLET_BASE_URL=${OIDF_WALLET_BASE_URL:-}
if [ -n "$WALLET_BASE_URL" ]; then
  WALLET_ISSUER_URL=${OIDF_WALLET_ISSUER_URL:-"${WALLET_BASE_URL%/}"}
elif [ "$WALLET_MANAGED" = "0" ]; then
  # An external wallet on a public https origin serves its issuer metadata
  # and status list on that same origin.
  WALLET_ISSUER_URL=${OIDF_WALLET_ISSUER_URL:-"${WALLET_URL%/}"}
else
  WALLET_ISSUER_URL=${OIDF_WALLET_ISSUER_URL:-"https://localhost:$((PORT + 1))"}
fi
WALLET_CA_CERT=${OIDF_WALLET_CA_CERT:-"$RUN_DIR/wallet-ca-cert.pem"}
CONFORMANCE_MODE=${CONFORMANCE_MODE:-local}
OIDF_WALLET_MODE=${OIDF_WALLET_MODE:-strict}
export OIDF_WALLET_MODE
OIDF_VCI_CLIENT_ID=${OIDF_VCI_CLIENT_ID:-52480754053}
OIDF_VCI_ALIAS=${OIDF_VCI_ALIAS:-"oid4vc-dev-vci-${PORT}"}

case "$CONFORMANCE_MODE" in
  local)
    CONFORMANCE_SERVER=${CONFORMANCE_SERVER:-https://localhost:8443/}
    CONFORMANCE_SERVER_LOCAL=${CONFORMANCE_SERVER_LOCAL:-https://localhost:8443/}
    CONFORMANCE_SERVER_MTLS=${CONFORMANCE_SERVER_MTLS:-https://localhost:8444/}
    CONFORMANCE_DEV_MODE=${CONFORMANCE_DEV_MODE:-1}
    DISABLE_SSL_VERIFY=${DISABLE_SSL_VERIFY:-1}
    ;;
  hosted)
    CONFORMANCE_SERVER=${CONFORMANCE_SERVER:-https://demo.certification.openid.net/}
    CONFORMANCE_SERVER_LOCAL=${CONFORMANCE_SERVER_LOCAL:-$CONFORMANCE_SERVER}
    CONFORMANCE_SERVER_MTLS=${CONFORMANCE_SERVER_MTLS:-$CONFORMANCE_SERVER}
    if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
      CONFORMANCE_TOKEN=${OIDF_TOKEN:-}
    fi
    if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
      echo "error: set OIDF_TOKEN in .env or export CONFORMANCE_TOKEN for CONFORMANCE_MODE=hosted" >&2
      exit 1
    fi
    ;;
  *)
    echo "error: CONFORMANCE_MODE must be local or hosted, got: $CONFORMANCE_MODE" >&2
    exit 1
    ;;
esac

export CONFORMANCE_SERVER CONFORMANCE_SERVER_LOCAL CONFORMANCE_SERVER_MTLS
if [ -n "${CONFORMANCE_TOKEN:-}" ]; then
  export CONFORMANCE_TOKEN
fi

OIDF_VCI_REDIRECT_URI=${OIDF_VCI_REDIRECT_URI:-"${CONFORMANCE_SERVER_LOCAL%/}/test/a/${OIDF_VCI_ALIAS}/callback"}

VENV_DIR="$RUN_DIR/venv"
RESULTS_DIR="$RUN_DIR/results"
RUNNER_LOG="$RUN_DIR/runner.log"
WALLET_LOG="$RUN_DIR/wallet.log"

mkdir -p "$RESULTS_DIR" "$WALLET_DIR"
if [ "$WALLET_MANAGED" = "1" ]; then
  build_local_eudi_dev
fi
fetch_suite_source

if [ "$CONFORMANCE_MODE" = "local" ]; then
  check_local_conformance_server
  export CONFORMANCE_DEV_MODE DISABLE_SSL_VERIFY
fi

# shellcheck disable=SC2329
cleanup() {
  if [ -n "${WALLET_PID:-}" ] && kill -0 "$WALLET_PID" 2>/dev/null; then
    kill "$WALLET_PID" 2>/dev/null || true
    wait "$WALLET_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "Using run directory: $RUN_DIR"

echo "Installing runner dependencies..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet -r "$SUITE_DIR/scripts/requirements.txt"
# The monitor verifies which credentials chain to the wallet CA (cbor2 reads
# the mdoc issuerAuth, cryptography checks the leaf against the CA).
"$VENV_DIR/bin/pip" install --quiet cbor2 cryptography

# The local suite competes for CPU with the wallet. Raise the remote timeout because a
# timed out flow cannot resume.
EUDI_REMOTE_TIMEOUT=${EUDI_REMOTE_TIMEOUT:-120s}
export EUDI_REMOTE_TIMEOUT

if [ "$WALLET_MANAGED" = "1" ]; then
  echo "Starting wallet on $WALLET_URL (remote timeout $EUDI_REMOTE_TIMEOUT)"
  (
    cd "$ROOT_DIR"
    if [ -n "$WALLET_BASE_URL" ]; then
      set -- --base-url "$WALLET_BASE_URL"
    else
      set --
    fi
    # The local suite's self-signed certificate has no subject alternative names.
    tls_verify=${OIDF_TLS_VERIFY:-}
    if [ -z "$tls_verify" ] && [ "$CONFORMANCE_MODE" = "local" ]; then
      tls_verify=false
    fi
    if [ -n "$tls_verify" ]; then
      set -- "$@" "--tls-verify=$tls_verify"
    fi
    if [ -n "${OIDF_TLS_CA:-}" ]; then
      set -- "$@" --tls-ca "$OIDF_TLS_CA"
    fi
    exec "$LOCAL_EUDI_DEV" wallet serve "$@" \
      --mode "$OIDF_WALLET_MODE" \
      --auto-accept \
      --pid \
      --preferred-format dc+sd-jwt \
      --wallet-dir "$WALLET_DIR" \
      --port "$PORT" \
      --vci-client-id "$OIDF_VCI_CLIENT_ID" \
      --vci-redirect-uri "$OIDF_VCI_REDIRECT_URI"
  ) >"$WALLET_LOG" 2>&1 &
  WALLET_PID=$!

  attempt=0
  until curl -fsS "$WALLET_URL/api/credentials" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if ! kill -0 "$WALLET_PID" 2>/dev/null; then
      echo "error: wallet exited before becoming ready" >&2
      cat "$WALLET_LOG" >&2
      exit 1
    fi
    if [ "$attempt" -ge 60 ]; then
      echo "error: wallet did not become ready" >&2
      exit 1
    fi
    sleep 1
  done
  # Export the CA through the API when the backend does not store it as a file.
  if [ ! -f "$WALLET_CA_CERT" ]; then
    if ! curl -fsS "$WALLET_URL/api/certificates/ca" -o "$WALLET_CA_CERT"; then
      echo "error: could not fetch the wallet CA from $WALLET_URL/api/certificates/ca" >&2
      exit 1
    fi
  fi
else
  echo "Using externally managed wallet at $WALLET_URL"
  if ! curl -fsS "$WALLET_URL/api/credentials" >/dev/null 2>&1; then
    echo "error: the wallet at $WALLET_URL does not answer /api/credentials" >&2
    exit 1
  fi
  # The external wallet's shared CA, fetched once. It anchors the wallet's
  # attestations and status list signatures in the generated configs.
  if [ ! -f "$WALLET_CA_CERT" ]; then
    if ! curl -fsS "$WALLET_URL/api/certificates/ca" -o "$WALLET_CA_CERT"; then
      echo "error: could not fetch the wallet CA from $WALLET_URL/api/certificates/ca" >&2
      exit 1
    fi
  fi
fi

echo "Running OIDF Final + HAIP wallet plans against $CONFORMANCE_SERVER ($CONFORMANCE_MODE mode)"
RUN_STATUS=0
"$VENV_DIR/bin/python" "$ROOT_DIR/scripts/oidf_wallet_conformance.py" \
  --suite-dir "$SUITE_DIR" \
  --wallet-url "$WALLET_URL" \
  --wallet-issuer-url "$WALLET_ISSUER_URL" \
  --wallet-ca-cert "$WALLET_CA_CERT" \
  --vci-client-id "$OIDF_VCI_CLIENT_ID" \
  --vci-redirect-uri "$OIDF_VCI_REDIRECT_URI" \
  --results-dir "$RESULTS_DIR" \
  --runner-log "$RUNNER_LOG" \
  "$@" || RUN_STATUS=$?

# Runs after a failed run too: a run that was killed leaves the most behind.
wipe_local_suite_database

echo "Wallet log:   $WALLET_LOG"
echo "Runner log:   $RUNNER_LOG"
echo "Results dir:  $RESULTS_DIR"

exit $RUN_STATUS
